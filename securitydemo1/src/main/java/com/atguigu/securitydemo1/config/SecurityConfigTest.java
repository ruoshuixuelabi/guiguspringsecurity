package com.atguigu.securitydemo1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.sql.DataSource;

/**
 * @author mazhenkun
 */
@Configuration
public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final DataSource dataSource;

    public SecurityConfigTest(UserDetailsService userDetailsService, DataSource dataSource) {
        this.userDetailsService = userDetailsService;
        this.dataSource = dataSource;
    }

    /**
     * 配置对象
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //退出
        http.logout().logoutUrl("/logout").
                logoutSuccessUrl("/test/hello").permitAll();
        //配置没有权限访问跳转自定义页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        //自定义自己编写的登录页面
        http.formLogin()
                //登录页面设置
                .loginPage("/on.html")
                //登录访问路径
                .loginProcessingUrl("/user/login")
                //登录成功之后，跳转路径
                .defaultSuccessUrl("/success.html").permitAll()
                .failureUrl("/unauth.html")
                .and().authorizeRequests()
                //设置哪些路径可以直接访问，不需要认证
                .antMatchers("/", "/test/hello", "/user/login").permitAll()
                //当前登录用户，只有具有admins权限才可以访问这个路径
                //1 hasAuthority方法
                // .antMatchers("/test/index").hasAuthority("admins")
                //2 hasAnyAuthority方法
                // .antMatchers("/test/index").hasAnyAuthority("admins,manager")
                //3 hasRole方法   ROLE_sale
                .antMatchers("/test/index").hasRole("sale")
                .anyRequest().authenticated()
                .and().rememberMe().tokenRepository(persistentTokenRepository())
                //设置有效时长，单位秒
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService);
        // .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // .and().csrf().disable();  //关闭csrf防护
    }
}
