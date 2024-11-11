package api.autenticacao.DTO;

import java.time.Instant;

public record TokenDTO (boolean valid, String token, String tokenType, String subject,
                        Instant expiration) {}