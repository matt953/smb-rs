use crate::msg_handler::IncomingMessage;
use crate::{error::*, sync_helpers::*};
use smb_transport::{IoVec, SmbTransport, SmbTransportRead, SmbTransportWrite, TransportError};
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, sync::oneshot};

use super::backend_trait::MultiWorkerBackend;
use super::base::ParallelWorker;

#[derive(Debug, Default)]
pub struct AsyncBackend {
    /// The loop handles for the workers.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,

    token: CancellationToken,
}

impl AsyncBackend {
    /// Internal message loop handler.
    async fn loop_receive(
        self: Arc<Self>,
        mut rtransport: Box<dyn SmbTransportRead>,
        worker: Arc<ParallelWorker<Self>>,
    ) {
        log::debug!("Starting receive loop");
        let self_ref = self.as_ref();
        let mut msg_count: u64 = 0;

        loop {
            match self_ref
                .handle_next_recv(rtransport.as_mut(), &worker)
                .await
            {
                Ok(_) => {
                    msg_count += 1;
                }
                Err(Error::TransportError(TransportError::NotConnected)) => {
                    log::error!("Connection force-closed after {} messages", msg_count);
                    self_ref.token.cancel();
                    break;
                }
                Err(Error::ConnectionStopped) => {
                    log::debug!("Connection stopped gracefully after {} messages", msg_count);
                    break;
                }
                Err(Error::TransportError(TransportError::Timeout(_))) => {
                    log::error!("Transport timeout after {} messages - treating as connection dead", msg_count);
                    self_ref.token.cancel();
                    break;
                }
                Err(e) => {
                    log::error!("Receive error after {} messages: {:?}", msg_count, e);
                }
            }
        }

        // Cleanup: notify awaiting tasks
        log::debug!("Receive loop cleanup, notifying awaiting tasks");
        if let Ok(mut state) = worker.state.lock().await {
            for (msg_id, tx) in state.awaiting.drain() {
                log::trace!("Notifying awaiting task {} of connection stop", msg_id);
                let _notify_result = tx.send(Err(Error::ConnectionStopped));
            }
        }
    }

    async fn loop_send(
        self: Arc<Self>,
        mut wtransport: Box<dyn SmbTransportWrite>,
        mut send_channel: mpsc::Receiver<IoVec>,
        worker: Arc<ParallelWorker<Self>>,
    ) {
        log::debug!("Starting send loop");
        let self_ref = self.as_ref();
        let mut msg_count: u64 = 0;

        loop {
            match self_ref
                .handle_next_send(wtransport.as_mut(), &mut send_channel, &worker)
                .await
            {
                Ok(_) => {
                    msg_count += 1;
                }
                Err(Error::TransportError(TransportError::NotConnected)) => {
                    log::error!("Connection force-closed after {} messages", msg_count);
                    self_ref.token.cancel();
                    break;
                }
                Err(Error::ConnectionStopped) => {
                    log::debug!("Connection stopped gracefully after {} messages", msg_count);
                    break;
                }
                Err(e) => {
                    log::error!("Send error after {} messages: {:?}", msg_count, e);
                }
            }
        }

        log::debug!("Closing send channel");
        send_channel.close();
    }

    /// Handles the next message in the receive loop:
    /// receives a message, transforms it, and sends it to the correct awaiting task.
    ///
    /// - If the connection is stopped using the `stop` method, this will return `Error::ConnectionStopped`.
    /// - A [`TransportError`] might be returned if the underlying transport fails.
    async fn handle_next_recv(
        &self,
        rtransport: &mut dyn SmbTransportRead,
        worker: &Arc<ParallelWorker<Self>>,
    ) -> crate::Result<()> {
        select! {
            biased;

            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::ConnectionStopped)
            }

            // Receive a message from the server.
            message_from_server = rtransport.receive() => {
                worker.incoming_data_callback(message_from_server).await
            }
        }
    }

    /// Handles the next message in the send loop:
    /// sends a message to the server.
    async fn handle_next_send(
        &self,
        wtransport: &mut dyn SmbTransportWrite,
        send_channel: &mut mpsc::Receiver<IoVec>,
        worker: &Arc<ParallelWorker<Self>>,
    ) -> crate::Result<()> {
        select! {
            // Send a message to the server.
            message_to_send = send_channel.recv() => {
                worker.outgoing_data_callback(message_to_send, wtransport).await
            },
            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::ConnectionStopped)
            }
        }
    }
}

impl MultiWorkerBackend for AsyncBackend {
    type SendMessage = IoVec;

    type AwaitingNotifier = oneshot::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = oneshot::Receiver<crate::Result<IncomingMessage>>;

    async fn start(
        transport: Box<dyn SmbTransport>,
        worker: Arc<ParallelWorker<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>> {
        let backend: Arc<Self> = Default::default();
        let backend_clone = backend.clone();
        let (rtransport, wtransport) = transport.split()?;

        let recv_task = {
            let backend_clone = backend_clone.clone();
            let worker = worker.clone();
            tokio::spawn(async move { backend_clone.loop_receive(rtransport, worker).await })
        };

        let send_task = tokio::spawn(async move {
            backend_clone
                .loop_send(wtransport, send_channel_recv, worker)
                .await
        });
        backend
            .loop_handles
            .lock()
            .await?
            .replace((recv_task, send_task));

        Ok(backend)
    }

    async fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");
        self.token.cancel();
        let loop_handles = self
            .loop_handles
            .lock()
            .await?
            .take()
            .ok_or(Error::ConnectionStopped)?;
        loop_handles.0.await?;
        loop_handles.1.await?;
        Ok(())
    }
    fn wrap_msg_to_send(msg: IoVec) -> Self::SendMessage {
        msg
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        oneshot::channel()
    }

    async fn wait_on_waiter(
        waiter: Self::AwaitingWaiter,
        timeout: Duration,
    ) -> crate::Result<IncomingMessage> {
        if timeout == Duration::ZERO {
            waiter.await.map_err(|_| {
                Error::MessageProcessingError("Failed to receive message.".to_string())
            })?
        } else {
            tokio::select! {
                msg = waiter => {
                    msg.map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
                },
                _ = tokio::time::sleep(timeout) => {
                    Err(Error::OperationTimeout(TimedOutTask::ReceiveNextMessage, timeout))
                }
            }
        }
    }

    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()> {
        tx.send(msg).map_err(|_| {
            Error::MessageProcessingError("Failed to send message to awaiting task.".to_string())
        })
    }

    fn make_send_channel_pair() -> (
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    ) {
        mpsc::channel(100)
    }
}
