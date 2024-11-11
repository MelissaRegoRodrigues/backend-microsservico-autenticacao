package api.autenticacao.DTO;

import api.autenticacao.models.User;

import java.util.UUID;

public record UserDTO(
        String username,
        String email,
        String password
) {
    // Método para converter de User para UserDTO
    public static UserDTO fromUser(User user) {
        return new UserDTO(
                user.getUsername(),
                user.getEmail(),
                user.getPassword()
        );
    }
}