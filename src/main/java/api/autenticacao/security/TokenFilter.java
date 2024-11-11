package api.autenticacao.security;

import api.autenticacao.DTO.TokenDTO;
import api.autenticacao.services.UserService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.UUID;

//modelo de filtro, a gente vai usar isso nos microsserviços que precisam de autenticação
@Component
public class TokenFilter extends OncePerRequestFilter {

    private final UserService userDetailsService;
    private final JwtTokenProvider tokenService;

    @Autowired
    public TokenFilter(UserService userDetailsService, JwtTokenProvider tokenService) {
        this.userDetailsService = userDetailsService;
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response,
                                    @Nonnull FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);
        if (token != null) {
            TokenDTO tokenDTO = this.tokenService.validateToken(token);
            UserDetails user =  this.userDetailsService.obterUsuarioPorId(UUID.fromString(tokenDTO.subject()));

            if (user == null) filterChain.doFilter(request,response);

            var authentication = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private String extractToken(@Nonnull HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null) return null;
        return authorization.replace("Bearer ", "");
    }
}

