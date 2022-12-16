<div align="center">
    <img src="docs/assets/img/logo-animated.svg" width="192" alt="logo" />
    <h1>Nextcloud</h1>
    <h4>Скрипт установки набора клиент-серверных программ на Debian/Ubuntu</h4>
</div>


### Обзор

Данный скрипт предназначен для установки **Nextcloud 25** - набора клиент-серверных программ для создания и использования хранилища данных.

Официальный сайт **Nextcloud**: [https://nextcloud.com](https://nextcloud.com)

ПО может быть установлено как на удалённом хостинге, так и на собственном сервере.



Если у Вас нет подготовленного сервера, но Вы хотите попрактиковаться в быстром развёртывании **Nextcloud** на удалённом сервере, Вам сможет помочь отличный хостинг-провайдер **Digitalocean**, имеющий быстрые качественные сервера во всех частях света.

Не работали ранее с **Digitalocean** ?! Присоединяйтесь и получайте бонус в **200 долларов США** на практические эксперименты! 

Для регистрации в **Digitalocean** перейдите [по этой ссылке](https://m.do.co/c/0ad0ed903f5e), следуйте инструкциям, и, после подтверждения Ваших учётных данных Вы получите указанный бонус ($200).

Затем создайте дроплет (VPS)

Это можно сделать в своём аккаунте или из консоли подобной командой:

```shell
curl -X POST -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer '$TOKEN'' \
    -d '{"name":"ubuntu-s-2vcpu-4gb-intel-fra1-01",
        "size":"s-2vcpu-4gb-intel",
        "region":"fra1",
        "image":"ubuntu-22-04-x64",
        "vpc_uuid":"52fafae5-c997-4dbf-b958-3ab9cc16e871"}' \
    "https://api.digitalocean.com/v2/droplets"
```


### Подготовка сервера к установке




### Установка

1. Подключаемся к удалёному серверу по ssh:

```shell
ssh root@<IP-адрес>
```

где <IP-адрес> - адрес Вашего удалённого сервера

Если Вы заходите на свой сервер не от имени root пользователя, перед установкой необходимо переключиться на `root` пользователя:

```shell
sudo -s
```


2. Клонируйте текущий репозиторий на сервер:

```shell
git clone https://github.com/slavakoreshkov/nextcloud-server
```


3. Скопируйте установочнй скрипт в корень проекта:

```shell
cp nextcloud-server/install.sh .
```


4. Дайте разрешение на выполнение установочного скрипта:

```shell
```shell
chmod +x install.sh
```

5. Во избежание сбоев в установке, проверьте корректность всех переменных скрипта, а именно:

+ `NC_DATA_PATH` - Абсолютный путь к директории хранения данных Nextcloud
+ `NC_ADMIN_USER` - Произвольное имя администратора Nextcloud
+ `NC_ADMIN_USER_PASSWORD` - Генерация надёжного пароля для администратора Nextcloud
+ `NC_RELEASE` - Устанавливаемая версия Nextcloud
+ `PHP_VERSION` - Используемая версия PHP
+ `USE_LET_S_ENCRYPT` - Подтверждение настройки сертификатов Let's Encrypt
+ `NC_DNS` - доменное имя Nextcloud
+ `MARIADB_ROOT_PASSWORD` - 
+ `DATABASE` - Выбор реляционной СУБД для хранения данных ( MariaDB || PostgreSQL )
+ `NC_DB_USER` - Имя пользователя БД
+ `NC_DB_PASSWORD` - Генерация надёжного пароля для пользователя БД
+ `CURRENT_TIMEZONE` - Определяем часовой пояс сервера
+ `PHONE_REGION` - Значение по умолчанию региона телефона
+ `INCLUDING_NC_OFFICE` - Включение офисного пакета NEXTCLOUD OFFICE в комплект установки
+ `INCLUDING_ONLY_OFFICE` - Включение офисного пакета ONLYOFFICE в комплект установки
+ `CURRENT_USERNAME` - Определение текущего пользователя


6. Запустите скрипт:

```shell
./install.sh
```

Проявите терпение - минут 7-8... 

По завершении выполнения скрипта, в консоли на финальном экране Вы увидите все необходимые учётные данные для дальнейшей работы с **Nextcloud**.

Сохраните в надёжном месте эти данные:

+ IP-адрес сервера
+ Ссылки на домен
+ Имя пользователя / пароль администратора Nextcloud
+ Инструкции по сбросу пароля
+ Путь к данным **Nextcloud**
+ СУБД: Наименование / Имя пользователя / ROOT-пароль  

Наконец, приступайте к изучению возможностей многочисленных сервисов **Nextcloud**

Гостевой вход на сайт: [https://nextcloud.domain-demo.tk](https://nextcloud.domain-demo.tk)

Логин: `guest@example.com`

Пароль: `Guest!2345`

<br>
<hr>
<div align="center">
    <h3>Есть какие-либо вопросы?</h3>
    <a href="https://github.com/slavakoreshkov/nextcloud-server/issues"><img src="https://img.shields.io/badge/Справшивай-НЕ СТЕСНЯЙСЯ!!!-FF6600.svg?style=for-the-badge&link=https://github.com/slavakoreshkov/slavakoreshkovq/issues"/></a>
</div>


