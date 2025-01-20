# API REST para un foro

Este proyecto implementa una API REST para un foro utilizando Java y Spring Boot. La API permite a los usuarios realizar las siguientes acciones:

* Listar tópicos
* Crear un nuevo tópico
* Eliminar un tópico

## Tecnologías utilizadas

* Java
* Spring Boot
* Spring Data JPA
* Spring Security
* JWT (JSON Web Tokens)
* H2 Database (base de datos embebida)

## Cómo ejecutar el proyecto

1. Clona el repositorio: `git clone https://github.com/tu-usuario/foro.git`
2. Compila el proyecto: `mvn clean install`
3. Ejecuta la aplicación: `mvn spring-boot:run`

La API estará disponible en `http://localhost:8080`.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/topicos` | Lista todos los tópicos |
| POST | `/topicos` | Crea un nuevo tópico |
| DELETE | `/topicos/{id}` | Elimina el tópico con el ID especificado |
| POST | `/auth/login` | Autentica a un usuario y genera un token JWT |
| POST | `/auth/registrar` | Registra un nuevo usuario |

## Seguridad

La API utiliza tokens JWT para la autenticación. Para acceder a los endpoints protegidos, debes incluir el token JWT en la cabecera `Authorization` de la solicitud.

## Ejemplo de uso

**Crear un nuevo tópico:**

POST /topicos HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{
"titulo": "Nuevo tópico",
"mensaje": "Este es un nuevo tópico",
"autor": "Juan Pérez",
"curso": "Spring Boot"
}


**Eliminar un tópico:**

DELETE /topicos/1 HTTP/1.1
Authorization: Bearer <token>


## Contribuciones

Las contribuciones son bienvenidas. Por favor, crea un pull request con tus cambios.

## Licencia

Este proyecto está licenciado bajo la licencia MIT.
