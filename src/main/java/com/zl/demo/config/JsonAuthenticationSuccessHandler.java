package com.zl.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zl.demo.entity.User;
import com.zl.demo.util.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * @author tzxx
 */
public class JsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) authentication;
        UserDetailsImpl userDetails = (UserDetailsImpl) authenticationToken.getPrincipal();
        String token = JWTUtil.sign(userDetails.getUsername(), userDetails.getPassword());
        User user = new User();
        user.setToken(token);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(user));
    }
}
