#![allow(warnings)]

// stub file with MVP functions
// TODO: осознать и переработать "как положено"

// TODO: Создать структуры/перечисления для удобного управления жизненным циклом коробки/анализа
// прийти к конечным стейтам и хранению ключевой информации о коробках

// TODO: настроить логирование каждого статуса
// например, создание сети, создание раздела, создание контейнера,
// уничтожение контейнера, ошибки при создании и удалении контейнеров и так далее

//TODO: использовать docker pause для считывания дампа процесса


use std::os::unix::fs as unix_fs;
use std::{fs, result};
use nix::unistd::{User, Group};
use std::os::unix::fs::chown;
use std::path::Path;

use bollard::models::{HostConfig, RestartPolicy, RestartPolicyNameEnum};

use bollard::query_parameters::{CreateContainerOptions, InspectContainerOptions, InspectContainerOptionsBuilder, RemoveVolumeOptionsBuilder};
// use bollard::volume::CreateVolumeOptions;
use std::collections::HashMap;
use bollard::errors::Error;

use bollard::models::*;
use bollard::Docker;
use bollard::query_parameters::StopContainerOptionsBuilder;
use bollard::query_parameters::RemoveContainerOptionsBuilder;
use bollard::query_parameters::RemoveContainerOptions;
use bollard::query_parameters::RemoveVolumeOptions;
use crate::models::ConnectionInfo;
use crate::models::Privileges;


// initiates box with default config:
// 1. box
// 2. vnc (mgr)
// 3. sniffer

/*
TODO: создание структуры папок - типа:

/opt/pokey/boxes/UUID/artefacts/filesystem
/opt/pokey/boxes/UUID/artefacts/traffic

файл уже будет лежать:
/opt/pokey/boxes/UUID/object/<file>

*/



pub async fn init_box(uuid: &str, link: &str) -> Result<ConnectionInfo, Error> {
    
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let vol_name = format!("pokey-vol-x11-{}", uuid);
    let net_isolated = format!("pokey-net-isolated-{}", uuid);
    let net_guacd = format!("pokey-net-guacd-{}", uuid);
    let box_name = format!("pokey-box-{}", uuid);
    let manager_name = format!("pokey-manager-{}", uuid);
    let gemini_name = format!("pokey-gemini-{}", uuid);




    // volumes init:
    let volume_config = VolumeCreateRequest {
        name: Some(vol_name.clone()),
        driver: Some("local".to_string()),
        ..Default::default()
    };
    docker.create_volume(volume_config).await.unwrap();


    // networks init:
    let net_default = NetworkCreateRequest {
        driver: Some("bridge".to_string()),
        ..Default::default() 
    };

    docker.create_network(NetworkCreateRequest {name: net_isolated.clone(), ..net_default.clone() }).await.unwrap();
    docker.create_network(NetworkCreateRequest {name: net_guacd.clone(), ..net_default.clone() }).await.unwrap();
    

    // TODO: images build


    // containers init:

    // box
    let box_host_config = HostConfig {
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::ALWAYS),
            ..Default::default()
        }),
        binds: Some(vec![format!("{}:/tmp/.X11-unix", vol_name)]),
        network_mode: Some(net_isolated.clone()),
        ..Default::default()
    };

    let box_config = ContainerCreateBody {
        image: Some("pokey/box-web:0.0.1".to_string()),
        host_config: Some(box_host_config),
        env: Some(vec![
            format!("START_URL={}", link),
        ]),
        ..Default::default()
    };

    docker.create_container(
        Some(CreateContainerOptions { name: Some(box_name.clone()), platform: "".to_string() }), 
        box_config
    ).await.unwrap();
    
    docker.start_container(&box_name, None).await.unwrap();


    // gemini
    let p = Privileges::init();
    p.drop().unwrap();
    let path = format!("/opt/pokey/boxes/artefacts/{}/traffic/", uuid);
    let _ = fs::create_dir_all(path.clone());
    p.escalate().unwrap();

    let gemini_host_config = HostConfig {
        restart_policy: Some(bollard::service::RestartPolicy {
            name: Some(bollard::service::RestartPolicyNameEnum::ALWAYS),
            ..Default::default()
        }),
        network_mode: Some(format!("container:{}", box_name)),
        binds: Some(vec![format!("{}:/logs/", path)]),
        ..Default::default()
    };

    let gemini_config = ContainerCreateBody {
        image: Some("pokey/gemini:0.0.1".to_string()),
        host_config: Some(gemini_host_config),
        ..Default::default()
    };

    docker.create_container(Some(CreateContainerOptions { name: Some(gemini_name.clone()), platform: "".to_string() }), gemini_config).await.unwrap();
    docker.start_container(&gemini_name, None).await.unwrap();


    // manager
    let manager_host_config = HostConfig {
        restart_policy: Some(bollard::service::RestartPolicy {
            name: Some(bollard::service::RestartPolicyNameEnum::ALWAYS),
            ..Default::default()
        }),
        binds: Some(vec![format!("{}:/tmp/.X11-unix:rw", vol_name)]),
        network_mode: Some(net_guacd.clone()),
        ..Default::default()
    };

    let manager_config = ContainerCreateBody {
        image: Some("pokey/manager:0.0.1".to_string()),
        host_config: Some(manager_host_config),
        ..Default::default()
    };

    docker.create_container(Some(CreateContainerOptions { name: Some(manager_name.clone()), platform: "".to_string() }), manager_config).await.unwrap();

    let connect_opts = NetworkConnectRequest {
        container: "pokey-guacd".to_string(),
        ..Default::default()
    };
    if let Err(e) = docker.connect_network(&net_guacd, connect_opts).await {
        println!("Не удалось подключить сеть: {}", e);
    }

    docker.start_container(&manager_name, None).await?;


    let inspect = docker.inspect_container(&manager_name, None).await.unwrap();
    let ip_address = inspect.network_settings
        .and_then(|ns| ns.networks)
        .and_then(|mut nets| nets.remove(&net_guacd)) // remove забирает значение, избегая лишнего клонирования
        .and_then(|net_config| net_config.ip_address)
        .filter(|ip| !ip.is_empty()); // Отсекаем пустые строки, если контейнер еще не получил IP

    if let Some(ip) = ip_address {
        // println!("ipv4_addr: {}", ip);

        let ipv4: std::net::Ipv4Addr = ip.parse().map_err(|_| {
            bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                message: format!("Container '{}' did not receive an IP address in network '{}'", 
                manager_name, net_guacd)}
        })?;

        Ok(ConnectionInfo {
            ip: ipv4,
            port: 5900,
            protocol: "vnc".to_string(),       
            hostname: "".to_string()
        })
    } else {
        Err(bollard::errors::Error::DockerResponseServerError {
        status_code: 404,
        message: format!("Container '{}' did not receive an IP address in network '{}'", manager_name, net_guacd),
    })
    }
    
}

pub async fn collect_artefacts(uuid: &str) -> Result<HashMap<i32, String>, Error> {
    let p = Privileges::init();
    p.drop().unwrap();
    
    let docker = Docker::connect_with_socket_defaults().unwrap();
    
    let vol_name = format!("pokey-vol-x11-{}", uuid);
    let net_isolated = format!("pokey-net-isolated-{}", uuid);
    let net_guacd = format!("pokey-net-guacd-{}", uuid);
    let box_name = format!("pokey-box-{}", uuid);
    let manager_name = format!("pokey-manager-{}", uuid);
    let gemini_name = format!("pokey-gemini-{}", uuid);
    let app_path = format!("/opt/pokey");

    p.escalate().unwrap();
    let box_inspect = docker.inspect_container(&box_name, None).await.unwrap();
    p.drop().unwrap();

    let box_upper_dir = box_inspect.graph_driver.unwrap().data.get("UpperDir").unwrap().clone();
    println!("\nbox_upper_dir: {}", box_upper_dir);
    
    p.escalate().unwrap();
    let box_diff = match docker.container_changes(&box_name).await.unwrap() {
        Some(vec) => vec,
        None => vec![], 
    };
    p.drop().unwrap();
    
    println!("\nbox_diff: {:?}", box_diff);
    // let artefacts = vec![];
    let mut counter = 11;
    let mut result: HashMap<i32, String> = HashMap::new();


    for fs_change in box_diff {
        let fullpath = box_upper_dir.clone() + &fs_change.path;
        println!("FULLPATH: {}", fullpath);

        p.escalate().unwrap();
        // 1. Используем symlink_metadata, чтобы не падать на битых ссылках
        let metadata = match fs::symlink_metadata(&fullpath) {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("\tОшибка получения метаданных для {}: {}", fullpath, e);
                p.drop().unwrap();
                continue; // Пропускаем проблемный файл
            }
        };
        p.drop().unwrap();

        let target_path = format!("{}/boxes/{}/artefacts/fs{}", app_path, uuid, &fs_change.path);
        let path = Path::new(&target_path);

        if metadata.is_dir() {
            println!("processing dir: {}", fs_change.path);
            println!("\tcreating dir: {}\n", &target_path);
            let _ = fs::create_dir_all(path);
        } 
        else if metadata.file_type().is_symlink() {
            println!("processing symlink: {}", fs_change.path);
            p.escalate().unwrap();
            
            // Читаем, куда указывает оригинальная ссылка
            match fs::read_link(&fullpath) {
                Ok(target_link) => {
                    println!("\tcreating symlink: {} -> {:?}", target_path, target_link);
                    // Удаляем старый файл/ссылку, если она осталась с прошлого раза, чтобы не было ошибки
                    let _ = fs::remove_file(path); 
                    
                    // Создаем точно такую же ссылку в целевой директории
                    if let Err(e) = unix_fs::symlink(target_link, path) {
                        eprintln!("\tОшибка создания симлинка: {}", e);
                    }
                }
                Err(e) => eprintln!("\tНе удалось прочитать симлинк {}: {}", fullpath, e),
            }
            p.drop().unwrap();
            println!("OK\n");
        } 
        else {
            // Обычный файл
            println!("processing fil: {}", fs_change.path);
            println!("\thardlinking : {}", target_path);
            
            p.escalate().unwrap();
            let _ = fs::remove_file(path);

            if let Err(e) = fs::hard_link(&fullpath, path) {
                eprintln!("\tОшибка hardlink: {}", e);
                p.drop().unwrap();
                continue;
            }

            if let Ok(Some(user)) = User::from_name("user") {
                let uid = user.uid.as_raw();
                let gid = Group::from_name("user").ok().flatten().map(|g| g.gid.as_raw()).unwrap_or(0);

                if let Err(e) = chown(path, Some(uid), Some(gid)) {
                    eprintln!("\tОшибка chown: {}", e);
                } else {
                    println!("\t\tchown done");
                }
            }
            p.drop().unwrap();

            let is_sslkey = fs_change.path == "/home/appuser/sslkeys.log";

            if is_sslkey 
            {
                let extra_sslkey_path = format!("/opt/pokey/boxes/{}/artefacts/traffic/sslkeys.log", uuid);
                

                if let Some(parent) = Path::new(&extra_sslkey_path).parent() {
                    let _ = fs::create_dir_all(parent);
                };

                // let _ = fs::remove_file(&extra_sslkey_path);
                p.escalate().unwrap();

                if let Err(e) = fs::hard_link(&fullpath, &extra_sslkey_path) {
                    eprintln!("\tОшибка дополнительного hardlink для sslkey: {}", e);
                } else {
                    println!("\t\textra sslkey hardlink done");
                }
                let mut uid: u32 = 1000;
                let mut gid: u32 = 1000;
                
                if let Ok(Some(user)) = User::from_name("user") {
                    uid = user.uid.as_raw();
                    gid = Group::from_name("user").ok().flatten().map(|g| g.gid.as_raw()).unwrap_or(0);
                }
                // chown для дополнительного файла sslkey (если он был создан)
                if is_sslkey {
                    if let Err(e) = chown(&extra_sslkey_path, Some(uid), Some(gid)) {
                        eprintln!("\tОшибка chown для дополнительного sslkey: {}", e);
                    } else {
                        println!("\t\tchown extra sslkey done ");
                    }
                }

                p.drop().unwrap();
                print!("\t\twriting path to hashmap SSLKEYS");
                result.insert(2, extra_sslkey_path);
                println!("OK\n");
                continue;
            };


            print!("\t\twriting path to hashmap ");
            result.insert(counter, target_path);
            counter += 1;
            println!("OK\n");
        }
    };


    p.escalate().unwrap();

    if let Ok(Some(user)) = User::from_name("user") {
        let uid = user.uid.as_raw();
        let gid = Group::from_name("user").ok().flatten().map(|g| g.gid.as_raw()).unwrap_or(0);

        let gemini_logs_dir = format!("/opt/pokey/boxes/artefacts/{}/traffic/", uuid);

        println!("\tFixing gemini logs directory permissions...");

        let mut pcap_path = None;

        if let Ok(entries) = std::fs::read_dir(&gemini_logs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                // Меняем владельца для каждого файла
                let _ = chown(&path, Some(uid), Some(gid));

                // ПРОВЕРКА: Ищем файл с расширением .pcap
                if path.extension().map_or(false, |ext| ext == "pcap") {
                    // Сохраняем путь (конвертируем в String, если хэшмапа хранит строки)
                    if let Some(path_str) = path.to_str() {
                        pcap_path = Some(path_str.to_string());
                    }
                }
            }
        }
        
        // Не забываем поменять владельца самой папки
        let _ = chown(Path::new(&gemini_logs_dir), Some(uid), Some(gid));

        // Если нашли pcap файл, записываем его в хэшмапу под ключом 1
        if let Some(path) = pcap_path {
            println!("\tFound pcap file, writing to hashmap key 1: {}", path);
            result.insert(1, path);
        } else {
            eprintln!("\tПредупреждение: .pcap файл в папке {} не найден!", gemini_logs_dir);
        }
    }

    p.drop().unwrap();


    
    // number = 0 - главный объект
    // number = 1 - дамп трафика
    // number = 2 - sslkey.log файл

    // "number":"path"
    // number > 10 - первые 10 -зарезервированы под сам файл анализируемый, дамп памяти процессов, дамп трафика

    // пока что возвращаем hashmap, потом оформим в отдельную структуру при необходимости

    Ok(result)
}

pub async fn kill_box(uuid: &str) -> Result<i32, Error> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let vol_name = format!("pokey-vol-x11-{}", uuid);
    let net_isolated = format!("pokey-net-isolated-{}", uuid);
    let net_guacd = format!("pokey-net-guacd-{}", uuid);
    let box_name = format!("pokey-box-{}", uuid);
    let manager_name = format!("pokey-manager-{}", uuid);
    let gemini_name = format!("pokey-gemini-{}", uuid);


    let stop_options = StopContainerOptionsBuilder::default()
        .signal("SIGTERM")
        .t(15).build();


    let total_start = std::time::Instant::now(); // Общий таймер для всей пачки

    println!("\n[STOP] ---> Начинаем остановку контейнеров...");

    // 1. STOP BOX
    let start = std::time::Instant::now();
    println!("init_stopping: {}", box_name);
    let _ = docker.stop_container(&box_name, Some(stop_options.clone())).await;
    println!("stopped: {} (взяло: {:.2?})\n", box_name, start.elapsed());

    // 2. STOP MANAGER
    let start = std::time::Instant::now();
    println!("init_stopping: {}", manager_name);
    let _ = docker.stop_container(&manager_name, Some(stop_options.clone())).await;
    println!("stopped: {} (взяло: {:.2?})\n", manager_name, start.elapsed());
    
    // 3. STOP GEMINI
    let start = std::time::Instant::now();
    println!("init_stopping: {}", gemini_name);
    let _ = docker.stop_container(&gemini_name, Some(stop_options.clone())).await;
    println!("stopped: {} (взяло: {:.2?})", gemini_name, start.elapsed());

    println!("[STOP] <--- Все контейнеры обработаны. Общее время: {:.2?}\n", total_start.elapsed());

    // stop containers
    // println!("\ninit_stopping: {}", box_name);
    // docker.stop_container(&box_name.clone(), Some(stop_options.clone())).await;
    // println!("stopped: {}\n", box_name);

    // println!("init_stopping: {}", manager_name);
    // docker.stop_container(&manager_name.clone(), Some(stop_options.clone())).await;
    // println!("stopped: {}\n", manager_name);
    
    // println!("init_stopping: {}", gemini_name);
    // docker.stop_container(&gemini_name.clone(), Some(stop_options.clone())).await;
    // println!("stopped: {}", gemini_name);

    // remove network from guacd
    docker.disconnect_network(&net_guacd.clone(), 
        NetworkDisconnectRequest { container: "pokey-guacd".to_string(), force: Some(true) }).await;
    // docker.disconnect_network(&net_guacd.clone(), 
    //     NetworkDisconnectRequest { container: manager_name.clone(), force: Some(true) }).await;
    // docker.disconnect_network(&net_isolated.clone(), 
    //     NetworkDisconnectRequest { container: manager_name.clone(), force: Some(true) }).await;
    
    // remove containers
    let remove_container_options: bollard::query_parameters::RemoveContainerOptions = RemoveContainerOptionsBuilder::default()
        .force(true)
        .build();
    docker.remove_container(&manager_name, Some(remove_container_options.clone())).await;
    docker.remove_container(&gemini_name, Some(remove_container_options)).await;

    // remove networks
    let _ = docker.remove_network(&net_isolated).await;
    let _ = docker.remove_network(&net_guacd).await;

    // remove volumes - на данном этапе удалить volume без контейнера нельзя
    // let rm_vol_opts = RemoveVolumeOptions { force: true };
    // let _ = docker.remove_volume(&vol_name, Some(rm_vol_opts)).await;


    Ok(0)
}

pub async fn flush_box(uuid: &str) -> Result<i32, bollard::errors::Error> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let vol_name = format!("pokey-vol-x11-{}", uuid);
    let box_name = format!("pokey-box-{}", uuid);

    let rm_container_opts = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    let _ = docker.remove_container(&box_name, Some(rm_container_opts)).await;

    let rm_vol_opts = RemoveVolumeOptions { force: true };
    let _ = docker.remove_volume(&vol_name, Some(rm_vol_opts)).await;

    Ok(0)
}

// Хелпер для рекурсивной смены прав на файлы в папке после работы анализатора
fn fix_analysis_permissions(uuid: &str) {
    if let Ok(Some(user)) = User::from_name("user") {
        let uid = user.uid.as_raw();
        let gid = Group::from_name("user").ok().flatten().map(|g| g.gid.as_raw()).unwrap_or(0);

        let box_dir = format!("/opt/pokey/boxes/{}/", uuid);
        println!("\tFixing permissions for analysis directory: {}", box_dir);

        // chown для самой директории
        let _ = chown(Path::new(&box_dir), Some(uid), Some(gid));

        // chown для файлов внутри папки
        if let Ok(entries) = std::fs::read_dir(&box_dir) {
            for entry in entries.flatten() {
                let _ = chown(&entry.path(), Some(uid), Some(gid));
            }
        }
    }
}

pub async fn init_analysis(uuid: &str) -> Result<i32, Error> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let container_name = format!("foo-{}", uuid);
    let host_source_dir = format!("/opt/pokey/boxes/{}/", uuid);

    // Гарантируем наличие папки на хосте до старта
    let _ = fs::create_dir_all(host_source_dir.clone());

    // Инициализируем HostConfig с RW монтированием
    let host_config = HostConfig {
        binds: Some(vec![format!("{}:/app/data", host_source_dir)]),
        ..Default::default()
    };

    // Конфиг контейнера строго через ContainerCreateBody
    let container_config = ContainerCreateBody {
        image: Some("pokey/analysis:0.0.1".to_string()),
        cmd: Some(vec![
            "./app/pokey-analysis".to_string(),
            uuid.to_string(),
        ]),
        host_config: Some(host_config),
        ..Default::default()
    };

    // Создаем контейнер в твоем стиле
    docker.create_container(
        Some(CreateContainerOptions { name: Some(container_name.clone()), platform: "".to_string() }),
        container_config
    ).await.unwrap();

    // Подключаем к существующей сети "pokey-web"
    let connect_opts = NetworkConnectRequest {
        container: container_name.clone(),
        ..Default::default()
    };
    docker.connect_network("pokey-web", connect_opts).await.unwrap();

    // Запускаем контейнер
    docker.start_container(&container_name, None).await.unwrap();

    println!("Контейнер {} успешно запущен.", container_name);
    Ok(0)
}

pub async fn kill_analysis(uuid: &str) -> Result<i32, Error> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let container_name = format!("foo-{}", uuid);

    // 1. Принудительно тушим контейнер (SIGKILL)
    if let Err(e) = docker.kill_container(&container_name, None).await {
        println!("\tКонтейнер {} не работал или уже остановлен: {}", container_name, e);
    }

    // 2. Отключаем от сети pokey-web
    let disconnect_opts: NetworkDisconnectRequest = NetworkDisconnectRequest {
        container: container_name.clone(),
        force: Some(true),
    };
    if let Err(e) = docker.disconnect_network("pokey-web", disconnect_opts).await {
        println!("\tОшибка отключения контейнера {} от сети: {}", container_name, e);
    }

    // 3. Удаляем сам контейнер из докера
    let remove_opts = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    docker.remove_container(&container_name, Some(remove_opts)).await.unwrap();

    println!("Контейнер {} полностью удален.", container_name);

    // 4. Накатываем права пользователя "user" на созданные файлы
    fix_analysis_permissions(uuid);

    Ok(0)
}