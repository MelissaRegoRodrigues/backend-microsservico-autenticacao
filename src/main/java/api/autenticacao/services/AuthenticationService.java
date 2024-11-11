package api.autenticacao.services;

import api.autenticacao.DTO.LoginResponseDTO;
import api.autenticacao.DTO.TokenDTO;
import api.autenticacao.DTO.UserDTO;
import api.autenticacao.models.User;
import api.autenticacao.repositorios.UserRepository;
import api.autenticacao.security.JwtTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@AllArgsConstructor
@Service
public class AuthenticationService {

    // Dependências
    UserRepository userRepository;

    AuthenticationManager authManager;

    JwtTokenProvider tokenService;


    // Serviços
    public LoginResponseDTO authenticate(String email, String password) {
        try {
            var userNamePassword = new UsernamePasswordAuthenticationToken(email, password);
            authManager.authenticate(userNamePassword);

            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new UsernameNotFoundException("User not found with email: " + email);
            }

            UUID uid = user.getUserId();
            TokenDTO tokenDTO = tokenService.generateToken(uid.toString());
            UserDTO userDTO = UserDTO.fromUser(user);

            return new LoginResponseDTO(userDTO, tokenDTO);
        } catch (AuthenticationException e) {
            System.err.println("Erro de autenticação: " + e.getMessage());
            throw new BadCredentialsException("Email ou senha incorretos", e);
        }
    }


    public LoginResponseDTO validateToken(String token) {
        TokenDTO tokenDTO = tokenService.validateToken(extractToken(token));

        UUID userUid = UUID.fromString(tokenDTO.subject());
        UserDTO userDTO = UserDTO.fromUser(userRepository.findByUserId(userUid));

        return new LoginResponseDTO(userDTO, tokenDTO);
    }

    private String extractToken(String token) {
        if (token.contains("Bearer ")) {
            return token.replace("Bearer ", "");
        }
        return token;
    }

    public void registerUser(User user) {
        user.setPassword(encodePassword(user.getPassword()));

        this.userRepository.save(user);
    }

    private String encodePassword(String password) {
        return new BCryptPasswordEncoder().encode(password);
    }


}