/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.adaptors.jdbc;

import com.tceasy.common.utils.encrypt.AESUtil;
import com.tceasy.common.utils.encrypt.Base64;
import com.tceasy.common.utils.string.StringUtil;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import util.Md5ConverterUtil;

import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * Class that if provided a query that returns a password (parameter of query
 * must be username) will compare that password to a translated version of the
 * password provided by the user. If they match, then authentication succeeds.
 * Default password translator is plaintext translator.
 *
 * @author Scott Battaglia
 * @author Dmitriy Kopylenko
 * @author Marvin S. Addison
 *
 * @since 3.0.0
 */
public class QueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    private static String sql = "select GM_USER_ID,LOGIN,PASSWORD,NAME,TYPE,GM_COMPANY_ID from gm_user where state='1' and login=? ";

    /**
     * {@inheritDoc}
     */
    @Override
    protected final HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {

        String username = credential.getUsername();
        String password = credential.getPassword();


        password = Md5ConverterUtil.Md5(password);
        Object[] args = new Object[] { username };
                Map user = null;
        try{
            user = getJdbcTemplate().queryForMap(sql,args);
        }catch(Exception e){
            logger.error("错误原因 : {}",e);
            throw new FailedLoginException("Multiple records found for " + username);
        }
        if(user ==null){
            throw new FailedLoginException("Multiple records found for " + username);
        }
        if(user.get("PASSWORD") == null ){
            throw new FailedLoginException("Multiple records found for " + username);
        }

        if(!password.equals(user.get("PASSWORD"))){
            String pwd = "";
            try {
                if(StringUtil.isEmptyObj(user.get("GM_COMPANY_ID"))){
                    logger.info("用户GM_COMPANY_ID为空：{}",user.get("GM_COMPANY_ID"));
                    throw new FailedLoginException("用户GM_COMPANY_ID为空：" + user.get("GM_COMPANY_ID"));
                }
                String gmCompanyId = (String) user.get("GM_COMPANY_ID");
                if (gmCompanyId.length() != 32) {
                    logger.info("用户GM_COMPANY_ID长度不是32位：{}",gmCompanyId);
                    throw new FailedLoginException("用户GM_COMPANY_ID长度不是32位：" + gmCompanyId);
                }
                String credPwd = credential.getPassword();
                credPwd = new String(Base64.decode(credPwd));
                pwd = AESUtil.decrypt(credPwd,gmCompanyId);
                pwd = Md5ConverterUtil.Md5(pwd);
                if(pwd.equals(user.get("PASSWORD"))){
                    return createHandlerResult(credential,
                            this.principalFactory.createPrincipal(username), null);
                }
            } catch (Exception e) {
                logger.error("密码解析异常：{}",e);
            }
            throw new FailedLoginException("Multiple records found for " + username);
        }
        return createHandlerResult(credential,
                this.principalFactory.createPrincipal(username), null);
    }

    /**
     * @param sql The sql to set.
     */
    public void setSql(final String sql) {
        this.sql = sql;
    }
}
