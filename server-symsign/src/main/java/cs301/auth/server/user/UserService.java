package cs301.auth.server.user;

import java.util.*;

import javax.transaction.Transactional;
import org.springframework.beans.factory.annotation.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.*;
import cs301.auth.server.role.*;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserService implements UserDetailsService {
    @Autowired
    private final UserRepo users;
    @Autowired
    private final RoleRepo roles;
    
    @Autowired
    private final PasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO Auto-generated method stub
        User user = users.findByUsername(username);
        if (user == null) {
            log.error("User not found in the database ");
            throw new UsernameNotFoundException(username);
        } else {
            log.info("User found in the database {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                authorities);
    }

    public User saveUser(User user) {
        log.info("Saving new user to the db");
        user.setPassword(encoder.encode(user.getPassword()));
        return users.save(user);
    }

    public void addRoleToUser(String username, String roleName) {
        log.info("Saving new role{} to the user{}", roleName, username);
        User user = users.findByUsername(username);
        Role role = roles.findByName(roleName);
        user.getRoles().add(role);
    }

    public User getUser(String username) {
        log.info("reading the user from the db");
        return users.findByUsername(username);
    }

    public List<User> getUsers() {
        log.info("fetching all users from the db");
        return users.findAll();
    }
}
