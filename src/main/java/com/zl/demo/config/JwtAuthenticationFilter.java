package com.zl.demo.config;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.zl.demo.entity.User;
import com.zl.demo.util.JWTUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author tzxx
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION = "Authorization";
    private final RequestMatcher requiresAuthenticationRequestMatcher = new RequestHeaderRequestMatcher(AUTHORIZATION);
    private List<RequestMatcher> permissiveRequestMatchers;

    public JwtAuthenticationFilter(){}
    public JwtAuthenticationFilter(String... permissiveUrls){
        setPermissiveUrl(permissiveUrls);
    }

    protected String getJwtToken(HttpServletRequest request) {
        String authInfo = request.getHeader(AUTHORIZATION);
        return StringUtils.removeStart(authInfo, "Bearer ");
    }

    protected boolean permissiveRequest(HttpServletRequest request) {
        if(permissiveRequestMatchers == null){
            return false;
        }
        for(RequestMatcher permissiveMatcher : permissiveRequestMatchers) {
            if(permissiveMatcher.matches(request)){
                return true;
            }
        }
        return false;
    }


    public void setPermissiveUrl(String... urls) {
        if(permissiveRequestMatchers == null){
            permissiveRequestMatchers = new ArrayList<>();
        }
        for(String url : urls){
            permissiveRequestMatchers .add(new AntPathRequestMatcher(url));
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!requiresAuthenticationRequestMatcher.matches(request) || permissiveRequest(request)){
            filterChain.doFilter(request,response);
            return;
        }
        String token = getJwtToken(request);
        try {
            String username = JWTUtil.getUsername(token);
            if (StringUtils.isBlank(username)){
                throw new JWTDecodeException("token校验不通过");
            }
            // 通过用户名查询用户信息
            User user = User.generateUser(username);
            if (user == null){
                throw new UsernameNotFoundException("用户名错误");
            }
            if (!JWTUtil.verify(token, username, user.getPassword())){
                throw new JWTVerificationException("token校验不通过");
            }
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, "", user.authorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request,response);
        }catch (Exception e){
            //异常则没有认证 那么FilterSecurityInterceptor则会抛出异常，ExceptionTranslationFilter就捕获到了
            //ExceptionTranslationFilterAuthenticationEntryPoint就执行了
            filterChain.doFilter(request,response);
        }

    }
}
