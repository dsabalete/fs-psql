DROP TABLE IF EXISTS notes;

CREATE TABLE IF NOT EXISTS notes (
  id SERIAL PRIMARY KEY,
  content TEXT NOT NULL,
  important BOOLEAN,
  date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

insert into notes (content, important) values ('Relational databases rule the world', true);
insert into notes (content, important) values ('MongoDB is webscale', false);
