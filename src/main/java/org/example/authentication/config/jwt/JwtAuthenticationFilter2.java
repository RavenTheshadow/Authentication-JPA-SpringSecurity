//package org.example.authentication.config.jwt;
//
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class JwtAuthenticationFilter2 {
//    @Bean
//    public FilterRegistrationBean<JwtFilter> jwtAuthenticationFilter() {
//        FilterRegistrationBean<JwtFilter> filterRegistrationBean = new FilterRegistrationBean<>();
//        filterRegistrationBean.setFilter(new JwtFilter());
//
//        filterRegistrationBean.addUrlPatterns("/api/v1/restricted");
//
//        return filterRegistrationBean;
//    }
//}