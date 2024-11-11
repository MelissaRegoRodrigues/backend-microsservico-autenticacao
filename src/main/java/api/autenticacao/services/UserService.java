package api.autenticacao.services;

import api.autenticacao.models.User;
import api.autenticacao.repositorios.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.UUID;

@Service
public class UserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email);
    }

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> obterTodosUsuarios() {
        return userRepository.findAll();
    }

    public User obterUsuarioPorId(UUID id) {
        return userRepository.findByUserId(id);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByUsername(email);  // Se o e-mail for tratado como username
    }


    public User criarUsuario(User usuario) {
        return userRepository.save(usuario);
    }
}
