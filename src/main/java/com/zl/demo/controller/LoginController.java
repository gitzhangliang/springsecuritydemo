package com.zl.demo.controller;

import com.zl.demo.entity.User;
import com.zl.demo.util.JWTUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * @author zhangliang
 * @date 2021/9/24.
 */
@RestController
@RequestMapping
public class LoginController {

    @PostMapping("/login")
    public User login(@ModelAttribute User user) {
        user = User.generateUser(user.getUsername());
        String token = JWTUtil.sign(user.getUsername(), user.getPassword());
        user.setToken(token);
        return user;
    }

    /**前提：JsonUsernamePasswordAuthenticationFilter的continueChainBeforeSuccessfulAuthentication设为true
     * 使用JsonUsernamePasswordAuthenticationFilter处理登录之后，这一块代码会触发bad request 400，
     * 因为JsonUsernamePasswordAuthenticationFilter中已经读了一次request的inputstream（只能读一次）,所以这里
     * requst中已经没数据了。所以必须在JsonAuthenticationSuccessHandler中完成响应。
     *
     * JsonUsernamePasswordAuthenticationFilter的continueChainBeforeSuccessfulAuthentication设为false（默认），
     * 过滤器都断了，因为没有走chain.doFilter(request, response)，所以只能在JsonAuthenticationSuccessHandler处理
     * 		AbstractAuthenticationProcessingFilter#doFilter（）
     * 		if (continueChainBeforeSuccessfulAuthentication) {
     * 			chain.doFilter(request, response);
     *      }
     *
     *
     * 要么就像上边login方法那样，不要有任何filter处理（没开启formLogin,所以没有UsernamePasswordAuthenticationFilter）
     */
    @PostMapping("/jsonLogin")
    public User jsonLogin(@RequestBody User user) {
        return null;
    }


    @GetMapping("/view")
    public User view() {
        return User.generateUser("admin");
    }

    @GetMapping("/view/hasRole")
    @PreAuthorize("hasRole('audit')")
    public User viewHasRole() {
        return User.generateUser("admin");
    }

    @GetMapping("/view/hasAuthority")
    @PreAuthorize("hasAuthority('user::view')")
    public User viewHasAuthority() {
        return User.generateUser("admin");
    }
}
