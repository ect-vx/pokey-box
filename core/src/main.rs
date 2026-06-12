use futures_util::StreamExt;
use redis::{AsyncCommands, Commands};
use std::error::Error;

use crate::models::Privileges;
// use std::time::Duration;
mod helpers;
mod models;


const TO_CORE_PUBSUB: &str = "to_core";
const TO_WEB_PUBSUB: &str = "to_web";
// const TO_CORE_PUBSUB: &str = "123";


#[tokio::main(flavor = "current_thread")] // Один поток ОС, асинхронный рантайм
async fn main() -> Result<(), Box<dyn Error>> {
    let p = Privileges::init();
    p.drop().unwrap();

    let redis_client: redis::Client = redis::Client::open("redis://127.0.0.1/")?;
    let mut redis_tx = redis_client.get_connection()?;

    let mut pubsub = redis_client.get_async_pubsub().await?;
    pubsub.subscribe(TO_CORE_PUBSUB).await?;
    let mut message_stream = pubsub.on_message();

    println!("starting listener");
    while let Some(msg) = message_stream.next().await
    {

        let uuid: String = match msg.get_payload() 
        {
            Ok(val) => val,
            Err(_) => continue,
        };

        println!("sub_signal:check: {}", uuid.clone());

        let hash_key = format!("analysis:{}", uuid.clone());
        let current_state: Option<i32> = redis_tx.hget(hash_key.clone(), "status")?;
        let link = redis_tx.hget::<&str, _, Option<String>>(&hash_key, "object")?
            .unwrap_or("https://example.com".to_string());


        println!("hash_key: {:?}\nstate: {:?}", hash_key, current_state);

        match current_state {
            Some(1) => {
                let _: () = redis_tx.hset(hash_key.clone(), "status", 2)?;

                
                p.escalate().unwrap();
                let connection = helpers::init_box(&uuid, &link).await?; // TODO
                p.drop().unwrap();

                let _: () = redis_tx.hset_multiple(hash_key.clone(), &[
                    ("status", "3"),
                    ("ip", &connection.ip.to_string()),
                    ("port", &connection.port.to_string()),
                    ("protocol", &connection.protocol.to_string()),
                ])?;
                let _: () = redis_tx.publish(TO_WEB_PUBSUB, uuid.clone())?;
                println!("Уведомление отправлено: {}", uuid.clone());
            }
            Some(4) => {
                println!("killing box {}", uuid.clone());
                let _: () = redis_tx.hset(hash_key.clone(), "status", 5)?;
                p.escalate().unwrap();
                let _ = helpers::kill_box(&uuid).await?;
                p.drop().unwrap();
                println!("killed box {}", uuid.clone());
                
                println!("collecting artefacts {}", uuid.clone());
                p.escalate().unwrap();
                let artefacts_files = helpers::collect_artefacts(&uuid).await?;
                p.drop().unwrap();
                println!("artefacts collected successfully {}", uuid.clone());

                println!("flushing box {}", uuid.clone());                
                p.escalate().unwrap();
                helpers::flush_box(&uuid).await?;
                p.drop().unwrap();
                println!("box flushed successfully {}", uuid.clone());

                let _: () = redis_tx.hset(hash_key.clone(), "status", 6)?;                
                println!("init analysis {}", uuid.clone());                
                // helpers::init_analysis(&uuid).await?;
                // println!("box flushed successfully {}", uuid.clone());
                
                

                
                // let _ = helpers::init_analysis(&uuid).await;

            }
            Some(8) => {
                helpers::kill_analysis(&uuid).await;

            }
            Some(any) => {
                eprintln!("Некорректный state: {}", any);
            }
            None => {
                eprintln!("State не найден для задачи: {}", uuid);
            }
        }

        
        


    }
    println!("stopping listener");

    Ok(())
}