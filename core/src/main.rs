use futures_util::StreamExt;
use redis::AsyncCommands;
use std::error::Error;
// use std::time::Duration;
mod helpers;



#[tokio::main(flavor = "current_thread")] // Один поток ОС, асинхронный рантайм
async fn main() -> Result<(), Box<dyn Error>> {
    let docker = bollard::Docker::connect_with_local_defaults()?;
    let redis_client: redis::Client = redis::Client::open("redis://127.0.0.1/")?;

    let mut pubsub = redis_client.get_async_pubsub().await?;
    pubsub.subscribe("to_core").await?;
    let mut message_stream = pubsub.on_message();

    let mut redis_tx = redis_client.get_async_connection().await?;

    while let Some(msg) = message_stream.next().await {

        let uuid: String = match msg.get_payload() {
            Ok(val) => val,
            Err(_) => continue,
        };

        println!("sub_signal:check: {}", uuid);
        let hash_key = format!("task:analysis:{}", uuid);

        let current_state: Option<i32> = redis_tx.hget(&hash_key, "state").await?;

        match current_state {
            Some(1) => {
                let stub = helpers::init_box(uuid.clone()).await; // TODO


                let _: () = redis_tx.publish("to_web", &uuid).await.unwrap();
                println!("Уведомление отправлено: {}", uuid);
            }
            Some(4) => {
                helpers::kill_box().await;

            }
            Some(8) => {
                helpers::kill_analysis().await;

            }
            Some(any) => {
                eprintln!("Некорректный state: {}", any);
            }
            None => {
                eprintln!("State не найден для задачи: {}", uuid);
            }
        }

        
        


    }

    Ok(())
}