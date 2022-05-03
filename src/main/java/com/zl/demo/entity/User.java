package com.zl.demo.entity;

import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

/**
 * @author tzxx
 */
@Data
public class User {

    private String username;
    private String password;

    private List<String> permissions;
    private List<String> roles;

    private String token;

    public static User generateUser(String username){
        if(StringUtils.isBlank(username)){
            return null;
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword("$2a$10$QXAh1KqZTcsV51MTIaCAcOje2KFEpClgl4Mzr8eyN0uMjGWEiFAGq");

        List<String> permissions = new ArrayList<>();
        permissions.add("user::add");
        permissions.add("user::view");
        user.setPermissions(permissions);

        List<String> roles = new ArrayList<>();
        roles.add("audit");
        roles.add("manage");
        user.setRoles(roles);
        return user;
    }

    public List<GrantedAuthority> authorities(){
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : this.getRoles()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
        }
        for (String permission : this.getPermissions()) {
            authorities.add(new SimpleGrantedAuthority(permission));
        }
        return authorities;
    }
}
