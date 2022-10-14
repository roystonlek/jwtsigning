package cs301.auth.server.user;

import java.util.*;

import javax.persistence.*;

import cs301.auth.server.role.Role;
import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor
public class User {
    @GeneratedValue(strategy = GenerationType.AUTO)@ Id
    private Long id;
    private String name;
    private String username;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles = new ArrayList<>();
}
