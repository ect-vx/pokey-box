use futures_util::StreamExt;
use redis::{AsyncCommands, Commands};
use std::error::Error;
// use std::time::Duration;
mod helpers;


const TO_CORE_PUBSUB: &str = "to_core";
const TO_WEB_PUBSUB: &str = "to_web";
// const TO_CORE_PUBSUB: &str = "123";


#[tokio::main(flavor = "current_thread")] // Один поток ОС, асинхронный рантайм
async fn main() -> Result<(), Box<dyn Error>> {
    let docker = bollard::Docker::connect_with_local_defaults()?;
    let redis_client: redis::Client = redis::Client::open("redis://127.0.0.1/")?;
    let mut redis_tx = redis_client.get_connection()?;

    let mut pubsub = redis_client.get_async_pubsub().await?;
    pubsub.subscribe(TO_CORE_PUBSUB).await?;
    let mut message_stream = pubsub.on_message();

    
    while let Some(msg) = message_stream.next().await
    {

        let uuid: String = match msg.get_payload() 
        {
            Ok(val) => val,
            Err(_) => continue,
        };

        println!("sub_signal:check: {}", uuid);

        let hash_key = format!("task:analysis:{}", uuid);
        let current_state: Option<i32> = redis_tx.hget(hash_key, "state").await?;

        println!("state: {}", current_state);

        match current_state {
            Some(1) => {
                redis_tx.hset(hash_key, "status", 2);
                let stub = helpers::init_box(uuid).await; // TODO

                


                let _: () = redis_tx.publish(TO_WEB_PUBSUB, uuid).await.unwrap();
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