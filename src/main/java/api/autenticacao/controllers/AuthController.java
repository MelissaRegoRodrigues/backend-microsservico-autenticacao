package api.autenticacao.controllers;

import api.autenticacao.DTO.LoginRequest;
import api.autenticacao.DTO.LoginResponseDTO;
import api.autenticacao.DTO.TokenDTO;
import api.autenticacao.models.User;
import api.autenticacao.security.JwtAuthenticationResponse;
import api.autenticacao.security.JwtTokenProvider;
import api.autenticacao.services.AuthenticationService;
import api.autenticacao.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;;
    private final JwtTokenProvider tokenProvider;
    private final UserService userService;

    @Autowired
    public AuthController(AuthenticationService authenticationService, JwtTokenProvider tokenProvider, UserService userService, UserService userService1) {
        this.authenticationService = authenticationService;
        this.tokenProvider = tokenProvider;
        this.userService = userService1;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequest authDTO) {
        LoginResponseDTO loginResponseDTO = authenticationService.authenticate(authDTO.getEmail(), authDTO.getPassword());
        System.out.println(loginResponseDTO);
        return ResponseEntity.ok().body(loginResponseDTO);
    }

    @GetMapping(value = "/validate-token")
    public ResponseEntity<LoginResponseDTO> validateToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        String token = authorizationHeader.replace("Bearer ", "");

        return ResponseEntity.ok(authenticationService.validateToken(token));
    }


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User registerRequest) {

        if (userService.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Usuário já existe!");
        }
        if (userService.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body("E-mail já está em uso!");
        }
        if (registerRequest.getPassword().length() < 6) {
            return ResponseEntity.badRequest().body("A senha deve ter pelo menos 6 caracteres.");
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(registerRequest.getPassword());

        authenticationService.registerUser(user);

        TokenDTO jwt = tokenProvider.generateToken(user.getUsername());
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt.token()));
    }
}
