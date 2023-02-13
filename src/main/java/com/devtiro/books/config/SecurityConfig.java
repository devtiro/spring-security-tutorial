package com.devtiro.books.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${devtiro.books.api-key.key}")
    private String principalRequestHeader;

    @Value("${devtiro.books.api-key.value}")
    private String principalRequestValue;

    @Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build());
		return manager;
	}

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        final ApiKeyAuthFilter filter = new ApiKeyAuthFilter(principalRequestHeader);
        filter.setAuthenticationManager((Authentication authentication) -> {
                final String principal = (String) authentication.getPrincipal();
                if (!principalRequestValue.equals(principal)) {
                    throw new BadCredentialsException("User did not provide valid API Key");
                }
                authentication.setAuthenticated(true);
                return authentication;
            }
        );

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable()
                .addFilter(filter).authorizeHttpRequests()
                .anyRequest().authenticated();

        return http.build();
    }

}
