alter table users add column if not exists password_hash text;
create index if not exists users_email_idx on users(lower(email));
