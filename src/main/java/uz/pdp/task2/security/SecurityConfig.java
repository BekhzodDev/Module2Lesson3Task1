package uz.pdp.task2.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("super_admin")
                .password(encoder().encode("super_admin"))
                .roles("SUPER_ADMIN")
                .and()
                .withUser("moderator")
                .password(encoder().encode("moderator"))
                .roles("MODERATOR")
                .and()
                .withUser("operator")
                .password(encoder().encode("operator"))
                .roles("OPERATOR");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/order/**").hasAnyRole("OPERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.POST, "/api/product/**").hasAnyRole("MODERATOR", "SUPER_ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/product/**").hasAnyRole("MODERATOR", "SUPER_ADMIN")
                .antMatchers("/api/**").hasRole("SUPER_ADMIN")
                .anyRequest().authenticated().and().httpBasic();
    }

    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }
}
