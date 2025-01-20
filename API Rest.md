# API Rest

- **`pom.xml`**: Este archivo define las dependencias del proyecto, como Spring Boot, Spring Web, Spring Data JPA, etc.
- **`Topico.java`**: Este archivo define la clase `Topico`, que representa un tópico en el foro. Incluirá atributos como título, mensaje, autor, etc.
- **`TopicoRepository.java`**: Este archivo define la interfaz `TopicoRepository`, que extiende `JpaRepository` para proporcionar operaciones CRUD para la entidad `Topico`.
- **`TopicoController.java`**: Este archivo define la clase `TopicoController`, que manejará las solicitudes HTTP relacionadas con los tópicos (listar, crear, eliminar, etc.).
- **`Usuario.java`**: Este archivo define la clase `Usuario`, que representa un usuario en el foro.
- **`UsuarioRepository.java`**: Este archivo define la interfaz `UsuarioRepository`, que extiende `JpaRepository` para proporcionar operaciones CRUD para la entidad `Usuario`.
- **`AutenticacionController.java`**: Este archivo define la clase `AutenticacionController`, que manejará la autenticación de usuarios y la generación de tokens JWT.
- **`SecurityConfig.java`**: Este archivo define la configuración de seguridad de la aplicación, incluyendo la autenticación JWT.

**A continuación, te muestro el código para cada archivo y una breve explicación:**

**`pom.xml`**

XML

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.0.1</version>
        <relativePath/> </parent>
    <groupId>com.example</groupId>
    <artifactId>foro</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>foro</name>
    <description>Demo project for Spring Boot</description>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

**Explicación:**

- Define las dependencias necesarias para el proyecto, incluyendo Spring Data JPA para la persistencia de datos, Spring Web para crear la API REST, Spring Security para la autenticación JWT, H2 database para la base de datos embebida y JJWT para la gestión de tokens JWT.

**`Topico.java`**

Java

```
package com.example.foro.modelo;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Topico {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String titulo;
    private String mensaje;
    private String autor;
    private String curso;

    public Topico() {
    }

    public Topico(String titulo, String mensaje, String autor, String curso) {
        this.titulo = titulo;
        this.mensaje = mensaje;
        this.autor = autor;
        this.curso = curso;
    }

    // Getters y setters
}
```

**Explicación:**

- Define la clase `Topico` con los atributos `id`, `titulo`, `mensaje`, `autor` y `curso`.
- La anotación `@Entity` indica que esta clase se mapea a una tabla en la base de datos.
- La anotación `@Id` indica que el atributo `id` es la clave primaria de la tabla.
- La anotación `@GeneratedValue` indica que el valor del atributo `id` se genera automáticamente.

**`TopicoRepository.java`**

Java

```
package com.example.foro.repositorio;

import com.example.foro.modelo.Topico;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TopicoRepository extends JpaRepository<Topico, Long> {
}
```

**Explicación:**

- Define la interfaz `TopicoRepository` que extiende `JpaRepository`.
- Esto proporciona métodos para realizar operaciones CRUD (Crear, Leer, Actualizar, Eliminar) en la entidad `Topico`.

**`TopicoController.java`**

Java

```
package com.example.foro.controlador;

import com.example.foro.modelo.Topico;
import com.example.foro.repositorio.TopicoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/topicos")
public class TopicoController {

    @Autowired
    private TopicoRepository topicoRepository;

    @GetMapping
    public List<Topico> listarTopicos() {
        return topicoRepository.findAll();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Topico crearTopico(@RequestBody Topico topico) {
        return topicoRepository.save(topico);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarTopico(@PathVariable Long id) {
        if (topicoRepository.existsById(id)) {
            topicoRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
```

**Explicación:**

- Define la clase `TopicoController` con los métodos para manejar las solicitudes HTTP relacionadas con los tópicos.
- `@GetMapping`: maneja las solicitudes GET para listar todos los tópicos.
- `@PostMapping`: maneja las solicitudes POST para crear un nuevo tópico.
- `@DeleteMapping("/{id}")`: maneja las solicitudes DELETE para eliminar un tópico por su ID.

**`Usuario.java`**

Java

```
package com.example.foro.modelo;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String nombre;
    private String email;
    private String contrasena;

    public Usuario() {
    }

    public Usuario(String nombre, String email, String contrasena) {
        this.nombre = nombre;
        this.email = email;
        this.contrasena = contrasena;
    }

    // Getters y setters
}
```

**Explicación:**

- Define la clase `Usuario` con los atributos `id`, `nombre`, `email` y `contrasena`.
- La anotación `@Entity` indica que esta clase se mapea a una tabla en la base de datos.
- La anotación `@Id` indica que el atributo `id` es la clave primaria de la tabla.
- La anotación `@GeneratedValue` indica que el valor del atributo `id` se genera automáticamente.

**`UsuarioRepository.java`**

Java

```
package com.example.foro.repositorio;

import com.example.foro.modelo.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Usuario findByEmail(String email);
}
```

**Explicación:**

- Define la interfaz `UsuarioRepository` que extiende `JpaRepository`.
- Esto proporciona métodos para realizar operaciones CRUD en la entidad `Usuario`.
- Además, define un método `findByEmail` para buscar un usuario por su email.

**`AutenticacionController.java`**

Java

```
package com.example.foro.controlador;

import com.example.foro.modelo.Usuario;
import com.example.foro.repositorio.UsuarioRepository;
import com.example.foro.seguridad.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AutenticacionController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UsuarioRepository usuarioRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, Object> credenciales) {
        try {
            String email = (String) credenciales.get("email");
            String contrasena = (String) credenciales.get("contrasena");
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, contrasena));
            String token = jwtUtil.generateToken(email);
            Map<String, Object> respuesta = new HashMap<>();
            respuesta.put("token", token);
            return ResponseEntity.ok(respuesta);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/registrar")
    public ResponseEntity<Map<String, Object>> registrar(@RequestBody Usuario usuario) {
        usuario.setContrasena(passwordEncoder.encode(usuario.getContrasena()));
        usuarioRepository.save(usuario);
        String token = jwtUtil.generateToken(usuario.getEmail());
        Map<String, Object> respuesta = new HashMap<>();
        respuesta.put("token", token);
        return ResponseEntity.status(HttpStatus.CREATED).body(respuesta);
    }
}
```

**Explicación:**

- Define la clase `AutenticacionController` con los métodos para manejar la autenticación de usuarios.
- `@PostMapping("/login")`: maneja las solicitudes POST para autenticar a un usuario y generar un token JWT.
- `@PostMapping("/registrar")`: maneja las solicitudes POST para registrar un nuevo usuario.

**`SecurityConfig.java`**

Java

```
package com.example.foro.seguridad;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JWTAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager auth) throws Exception {
        return http
                .csrf().disable()
                .httpBasic().disable()
                .cors()
                .and()
                .authorizeHttpRequests()
                .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/registrar").permitAll()
                .requestMatchers(HttpMethod.GET, "/topicos").permitAll()
                .anyRequest().authenticated()
                .and()
                .authenticationManager(auth)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    AuthenticationManager auth(HttpSecurity http, PasswordEncoder passwordEncoder) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder)
                .and()
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**Explicación:**

- Define la configuración de seguridad de la aplicación.
- `@EnableWebSecurity`: habilita la seguridad web.
- `filterChain`: configura las reglas de autorización para las diferentes rutas.
- `auth`: configura el `AuthenticationManager`.
- `passwordEncoder`: define el algoritmo de codificación de contraseñas.

**`JWTUtil.java`**

Java

```
package com.example.foro.seguridad;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JWTUtil {

    private String SECRET_KEY = "your-secret-key";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

**Explicación:**

- Define la clase `JWTUtil` con los métodos para generar y validar tokens JWT.
- `generateToken`: genera un

- `validateToken`: valida un token JWT.

**`UserDetailsServiceImpl.java`**

Java

```
package com.example.foro.seguridad;

import com.example.foro.modelo.Usuario;
import com.example.foro.repositorio.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmail(email);
        if (usuario == null) {
            throw new UsernameNotFoundException("Usuario no encontrado con email: " + email);
        }
        return new org.springframework.security.core.userdetails.User(usuario.getEmail(), usuario.getContrasena(), new ArrayList<>());
    }
}
```

**Explicación:**

- Define la clase `UserDetailsServiceImpl` que implementa `UserDetailsService`.
- `loadUserByUsername`: busca un usuario por su email y lo devuelve como un objeto `UserDetails`.

**`JWTAuthorizationFilter.java`**

Java

```
package com.example.foro.seguridad;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (ExpiredJwtException e) {
                // Manejar token expirado
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, userDetails)) {

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

**Explicación:**

- Define la clase `JWTAuthorizationFilter` que extiende `OncePerRequestFilter`.
- Este filtro intercepta las solicitudes HTTP, extrae el token JWT de la cabecera `Authorization`, valida el token y autentica al usuario.

**Recuerda:**

- Debes reemplazar `"your-secret-key"` en `JWTUtil.java` por una clave secreta segura.
- Puedes ajustar la configuración de seguridad en `SecurityConfig.java` según tus necesidades.
- Necesitas configurar una base de datos y actualizar las propiedades de conexión en el archivo `application.properties`.