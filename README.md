# pokey-box

Для тестирования вы можете использовать:

```shell
docker-compose up
```

Легковесная и простая в использовании песочница на базе Docker и контейнеризации. **pokey-box** предоставляет чистое, изолированное окружение для быстрого прототипирования, тестирования сервисов и экспериментов с мультиконтейнерными архитектурами без замусоривания хост-системы.

---

## Технический стек

* **Среда выполнения:** Docker
* **Оркестрация:** Docker Compose (с запланированным переходом на Docker Swarm)
* **Философия проекта:** Инфраструктура как код (IaC), минимальные накладные расходы, приоритет конфигурационных файлов над тяжелыми скриптами автоматизации.

---

## Особенности

* **Контейнерная изоляция:** Полное отделение экспериментальных сервисов, сетей и монтируемых томов от хост-машины.
* **Среды на базе Compose:** Запуск сложных топологий из нескольких контейнеров с помощью декларативных манифестов `docker-compose.yml`.
* **Легковесность и портативность:** Никаких тяжелых гипервизоров; если система поддерживает Docker, она запустит и `pokey-box`.
* **Готовность к Swarm (В будущем):** Архитектура проектируется с прицелом на масштабирование, чтобы легко перейти от тестирования на одном узле к распределенным кластерам.

---

## Структура каталогов

```
pokey-box/
├── .gitignore       # Исключает локальные логи, временные файлы и секреты из репозитория
├── LICENSE          # Условия лицензирования проекта
├── README.md        # Общее описание проекта и документация
└── soon...          # Будущие Dockerfile, файлы compose и конфигурации swarm
```

---

## План разработки (Roadmap)

- [ ] Базовые шаблоны Dockerfile для основных сред выполнения
- [ ] Готовые мультиконтейнерные сценарии с использованием Docker Compose
- [ ] Настройка сетевого взаимодействия и постоянного хранения данных (volumes) внутри песочницы
- [ ] Интеграция с Docker Swarm: Шаблоны для масштабирования сервисов и тестирования оркестрации на нескольких узлах

---

## TODO
- [ ] Интегрировать хранилище ключей вместо захардкоженных (хотя бы базовый dotenv)
- [ ] Разграничить доступы в redis (ACL)
- [ ] Разграничить доступы в PostgreSQL (ACL)
- [ ] Интегрировать поведенческий анализ
- [ ] Интегрировать gVisor
- [ ] Реализовать многопоточность в core
- [ ] Сборщик мусора в core компоненте


---

## Лицензия

Этот проект распространяется под лицензией MIT — подробности см. в файле LICENSE.












# pokey-box

A lightweight, minimal-friction sandbox environment based on Docker and containerization. **pokey-box** provides a clean, isolated room for rapid prototyping, service testing, and experimental multi-container environments without cluttering your host system.

---

## Technical Stack

* **Runtime:** Docker
* **Orchestration:** Docker Compose (with a planned roadmap for Docker Swarm)
* **Design Philosophy:** Infra-as-code, minimal overhead, configurations over heavy automation scripts.

---

## Features

* **Containerized Isolation:** Fully separate your experimental services, networking, and volume mounts from the host machine.
* **Compose-Driven Environments:** Spin up complex multi-container topologies using declarative `docker-compose.yml` blueprints.
* **Lightweight & Portable:** No heavy hypervisors; if it runs Docker, it runs `pokey-box`.
* **Swarm Ready (Future):** Designed with scalability in mind to transition from single-node testing to distributed clusters.

---

## Directory Structure

```
pokey-box/
├── .gitignore       # Prevents local logs, temporary files, and secrets from escaping
├── LICENSE          # Project licensing terms
├── README.md        # Project overview and documentation
└── soon...          # Upcoming Dockerfiles, compose setups, and swarm configurations
```

---

## Development Roadmap

- [ ] Core Dockerfile templates for basic runtimes
- [ ] Multi-container recipes using Docker Compose
- [ ] Networking and volume persistence best practices inside the sandbox
- [ ] Integration with Docker Swarm: Blueprints for scaling services and testing multi-node orchestration

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.