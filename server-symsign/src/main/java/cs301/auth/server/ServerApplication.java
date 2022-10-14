package cs301.auth.server;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import cs301.auth.server.role.Role;
import cs301.auth.server.role.RoleService;
import cs301.auth.server.user.*;

@SpringBootApplication
public class ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServerApplication.class, args);
	}

	// @Bean 
	// PasswordEncoder PasswordEncoder(){
	// 	return new BCryptPasswordEncoder();
	// }

	@Bean
	CommandLineRunner run(UserService userService,RoleService roleService){
		return args ->{
			roleService.addRole(new Role(null,"ROLE_USER"));
			roleService.addRole(new Role(null,"ROLE_ADMIN"));
			roleService.addRole(new Role(null,"ROLE_MANAGER"));
			roleService.addRole(new Role(null,"ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null,"johnn" , "johnnymama", "1234",new ArrayList<>()));
			userService.saveUser(new User(null,"tim" , "timymama", "1234",new ArrayList<>()));
			userService.saveUser(new User(null,"harry" , "harryymama", "1234",new ArrayList<>()));
			userService.saveUser(new User(null,"bob" , "bobymama", "1234",new ArrayList<>()));

			userService.addRoleToUser("timymama", "ROLE_ADMIN");
			userService.addRoleToUser("timymama", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("timymama", "ROLE_MANAGER");
			userService.addRoleToUser("timymama", "ROLE_USER");
		};
	}

	@Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

	

}
