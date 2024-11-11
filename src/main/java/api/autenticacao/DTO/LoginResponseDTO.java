package api.autenticacao.DTO;

public record LoginResponseDTO(UserDTO userDTO, TokenDTO tokenDTO) {
}
