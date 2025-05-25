use actix_web::{
    dev::ServiceRequest,
    delete,
    get,
    Error,
    post,
    put,
    web,
    App,
    HttpMessage,
    HttpResponse,
    HttpServer,
    Responder,
    middleware::from_fn,
};
use actix_cors::Cors;
use sqlx::{ postgres::PgPoolOptions, Pool, Postgres };
use serde::{ Deserialize, Serialize };
use dotenv::dotenv;
use std::{ env };
use jsonwebtoken::{ decode, encode, Header, Validation, DecodingKey, EncodingKey };
use chrono::{ Utc, Duration };
use bcrypt::verify;
// use bcrypt::{ hash, verify, DEFAULT_COST };

#[derive(Deserialize, Serialize, sqlx::FromRow)]
struct Todo {
    id: i32,
    name: String,
    iscomplete: bool,
}

#[derive(Deserialize)]
struct NewTodo {
    name: String,
    iscomplete: bool,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

struct JwtConfig {
    secret: String,
    expiration_secs: i64,
}

impl JwtConfig {
    fn new() -> Self {
        JwtConfig {
            secret: env::var("JWT_SECRET").expect("JWT secret must be set"),
            expiration_secs: 3600, // 1 hour
        }
    }
}

async fn init_db_pool() -> Pool<Postgres> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url).await
        .expect("Failed to create pool")
}

// Middleware to validate JWT
async fn jwt_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<actix_web::body::BoxBody>
) -> Result<actix_web::dev::ServiceResponse, Error> {
    let jwt_config = JwtConfig::new();
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| { actix_web::error::ErrorUnauthorized("No Authorization header") })?;

    let token = auth_header
        .to_str()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid header format"))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid Bearer token"))?;

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_config.secret.as_ref()),
        &Validation::default()
    ).map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?.claims;

    req.extensions_mut().insert(claims);

    next.call(req).await
}

#[post("/login")]
async fn login(pool: web::Data<Pool<Postgres>>, login: web::Json<LoginRequest>) -> impl Responder {
    let user = sqlx
        ::query_as::<_, User>("select id, username, password_hash from users where username = $1")
        .bind(&login.username)
        .fetch_optional(pool.get_ref()).await;

    match user {
        Ok(Some(user)) => if verify(&login.password, &user.password_hash).unwrap_or(false) {
            let jwt_config = JwtConfig::new();
            let claims = Claims {
                sub: user.id.to_string(),
                exp: (Utc::now() + Duration::seconds(jwt_config.expiration_secs)).timestamp(),
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(jwt_config.secret.as_ref())
            )
                .map_err(|_| HttpResponse::InternalServerError().body("Failed to generate token"))
                .unwrap();

            HttpResponse::Ok().json(TokenResponse { token })
        } else {
            HttpResponse::Unauthorized().body("Invalid credentials")
        }
        Ok(None) => HttpResponse::Unauthorized().body("User not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[get("/api/todos")]
async fn get_todos(pool: web::Data<Pool<Postgres>>) -> impl Responder {
    let todos = sqlx
        ::query_as::<_, Todo>("select id, name, iscomplete from public.todos")
        .fetch_all(pool.get_ref()).await;

    match todos {
        Ok(todos) => HttpResponse::Ok().json(todos),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[post("/api/todos")]
async fn create_todo(
    pool: web::Data<Pool<Postgres>>,
    new_todo: web::Json<NewTodo>
) -> impl Responder {
    println!("POST /api/todos");

    let result = sqlx
        ::query_as::<_, Todo>(
            "insert into public.todos (name, iscomplete) values ($1, $2) returning id, name, iscomplete"
        )
        .bind(&new_todo.name)
        .bind(&new_todo.iscomplete)
        .fetch_one(pool.get_ref()).await;

    match result {
        Ok(todo) => HttpResponse::Ok().json(todo),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[put("api/todos")]
async fn update_todo(pool: web::Data<Pool<Postgres>>, todo: web::Json<Todo>) -> impl Responder {
    let result = sqlx
        ::query_as::<_, Todo>("update public.todos set name = $2, iscomplete = $3 where id = $1")
        .bind(&todo.id)
        .bind(&todo.name)
        .bind(&todo.iscomplete)
        .fetch_optional(pool.get_ref()).await;

    match result {
        Ok(Some(todo)) => HttpResponse::Ok().json(todo),
        Ok(None) => HttpResponse::NotFound().body("Todo not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let pool = init_db_pool().await;

    // println!("{}", hash("admin", DEFAULT_COST).unwrap());

    println!("Starting server at http://127.0.0.1:8080");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors)
            .service(login)
            .service(
                web
                    ::scope("")
                    .wrap(from_fn(jwt_middleware))
                    .service(get_todos)
                    .service(create_todo)
                    .service(update_todo)
            )
    })
        .bind(("127.0.0.1", 8080))?
        .run().await
}
