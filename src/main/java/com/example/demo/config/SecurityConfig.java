package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
// webセキュリティー構成の仲介役
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// セキュリティ設定を、無視するパスを指定する
		// 通常、CSSやjs, imgなどのソースを指定する
		web.ignoring().antMatchers("/css/**", "/webjars/**");
	}

//	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
					//「/login」をアクセス可能にします
					.antMatchers("/login").permitAll()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					// ログイン時のURLを指定
					.loginPage("/login")
					//認証後にリダイレクトする場所を指定
					.defaultSuccessUrl("/")
					.and()
				// ログアウトの設定
				.logout()
					// ログアウト時のURLを指定
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
					.and()
				// Remember-me の認証を許可する。ブラウザを閉じて、再度開いた場合でもログインしたままになる
				.rememberMe();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			// ユーザ名と「admin」と「user」を用意する
			// パスワードは両方とも「password」です
			.withUser("admin")
				.password(passwordEncoder().encode("password"))
				.authorities("ROLE_ADMIN")
				.and()
			.withUser("user")
				.password(passwordEncoder().encode("password"))
				.authorities("ROLE_USER");
	}
	
}
