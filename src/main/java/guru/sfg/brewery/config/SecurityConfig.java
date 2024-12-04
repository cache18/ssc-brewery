package guru.sfg.brewery.config;

import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager manager) {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(manager);
        return filter;
    }

    public RestUrlAuthFilter restUrlParamAuthFilter(AuthenticationManager manager) {
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(manager);
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .csrf().disable(); //this is disabled globally so not needed again below

        http.addFilterBefore(restUrlParamAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class);

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**")
                                .hasAnyRole("ADMIN", "USER", "CUSTOMER")
                            .mvcMatchers("/brewery/breweries").hasAnyRole("CUSTOMER", "ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries")
                                .hasAnyRole("CUSTOMER", "ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}")
                                .hasAnyRole("ADMIN", "USER", "CUSTOMER")
                            .mvcMatchers("/beers/find", "/beers/{beerId}")
                                .hasAnyRole("ADMIN", "USER", "CUSTOMER");
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //do not needed anymore as PasswordEncoder and UserDetailsService are beans and SB can use them
    //to autoconfig for use
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                .password("{bcrypt}$2a$10$npfj68GW/fnQnTF3T6FcNe/43aBx5v9RHUI8Lo33yUEhZbjz30cDO")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                .password("{sha256}60c7a3719e5179d4083c2c5781ee24f6d232ffa59d8d2ac3d973aaf323493b11cf0f0dd4c6c70b62")
//                .roles("USER");
//
//        auth.inMemoryAuthentication()
//                .withUser("scott")
//                .password("{bcrypt10}$2a$10$MpnfnP9BZNucsDAMlwgw5.jII2VJkooqdw9rNZzCpp6huWebighJ2")
//                .roles("CUSTOMER");
//    }

    //    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }
}
