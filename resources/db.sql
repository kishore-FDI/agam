

create table users(
    id bigserial primary key,
    name text not null,
    email text not null,
    phone int unique not null,
    password text not null,
    created_timestamp default now()
);

create table vault(
    id uuid primary key default gen_random_uuid(),
    name text not null,
    type text not null,
    user_id uuid not null,
    created_timestamp default now()

    constraint user_id foreign key references users(id)
);

create table file(
    id uuid primary key default gen_random_uuid(),

    vault_id uuid not null,
    name text not null,
    type text not null,

    date date not null default current_date,
    time timestamp not null default now(),

    size int,

    minio_key text not null,
    thumbnail text

    constraint vault_file foreign key vault_id references vault(id) on delete cascade
);

create table sync_log(
    id uuid primary key default gen_random_uuid(),

    vault_id uuid not null,
    file_id uuid,
    last_updated timestamp not null default now(),
    device_id uuid not null,

    action text not null, --create, update delete

    constraint log_file foreign key file_id references file(id),
    constraint log_vault foreign key vault_id references vault(id),
    constraint log_device foreign key device_id references device(id)
);

create table device(
    id uuid primary key default gen_random_uuid(),
    name text not null,
    user_id uuid not null,
    created_timestamp default now(),

    constraint device_user foreign key user_id references users(id)
);