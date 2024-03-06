package com.example.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Objects;

public class CustomRealm extends AuthorizingRealm {

    /**
     * 自定义角色认证逻辑
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();

        // 这里可以编写自定义的角色认证逻辑，例如从数据库中获取用户的角色信息

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        if ("admin".equals(username)) {
            authorizationInfo.addRole("admin");
        } else if ("user".equals(username)) {
            authorizationInfo.addRole("user");
        }
        return authorizationInfo;
    }

    /**
     * 自定义身份认证逻辑
     *
     * @param authenticationToken 认证token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) authenticationToken;
        String username = usernamePasswordToken.getUsername();
        String password = String.valueOf(usernamePasswordToken.getPassword());

        if (Objects.equals(username, "admin") && Objects.equals(password, "admin")) {
            return new SimpleAuthenticationInfo(username, password, getName());
        }
        return null;
    }
}
