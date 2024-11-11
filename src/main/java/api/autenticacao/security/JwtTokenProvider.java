package api.autenticacao.security;

import api.autenticacao.DTO.TokenDTO;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationInMs;

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC256(jwtSecret);
    }

    public TokenDTO generateToken(String subject) {
        try {
            Instant currentInstant = getCurrentInstant();
            Instant expirationInstant = getExpirationTime(currentInstant);

            String token = JWT.create()
                    .withIssuedAt(currentInstant)
                    .withExpiresAt(expirationInstant)
                    .withSubject(subject)
                    .sign(getAlgorithm());

            return new TokenDTO(true, token, "Bearer", subject, expirationInstant);
        } catch (JWTCreationException exception) {
            throw new JWTCreationException("Não foi possível gerar um token válido", exception);
        }
    }

    /**
     * Valida o token fornecido
     * @param token que deseja verificar
     * @return {@link TokenDTO} com as informações do token retornado
     * @throws JWTVerificationException caso o token seja inválido
     */
    public TokenDTO validateToken(String token) {
        try {
            DecodedJWT decoded = JWT
                    .require(getAlgorithm())
                    .build()
                    .verify(token);

            Instant expiration = decoded.getExpiresAtAsInstant();

            return new TokenDTO(true, decoded.getSubject(), "Bearer", decoded.getSubject(), expiration);
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Token fornecido é inválido, pois possui credenciais " +
                    "incorretas", exception);
        }
    }

    private Instant getCurrentInstant() {
        return Instant.now();
    }
    private Instant getExpirationTime(Instant currentInstant) {
        return currentInstant.plusSeconds(jwtExpirationInMs);
    }
}
