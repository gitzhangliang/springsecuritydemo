package com.zl.demo.config;

import com.zl.demo.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * @author tzxx
 */
@Component
public class UserDetailsServiceImpl implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = User.generateUser(username);
        if(Objects.isNull(user)){
            throw new UsernameNotFoundException("用户不存在");
        }
        UserDetailsImpl details = new UserDetailsImpl();
        details.setUsername(user.getUsername());
        details.setPassword(user.getPassword());
        details.setAuthorities(user.authorities());
        return details;
    }
}
