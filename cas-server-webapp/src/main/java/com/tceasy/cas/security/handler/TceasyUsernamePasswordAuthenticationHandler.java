package com.tceasy.cas.security.handler;

import com.tceasy.common.utils.encrypt.AESUtil;
import com.tceasy.common.utils.encrypt.Base64;
import com.tceasy.common.utils.string.StringUtil;
import com.tceasy.util.Md5ConverterUtil;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.FailedLoginException;
import java.util.Map;

/**
 * Created by TJD on 2015/11/16.
 */
public class TceasyUsernamePasswordAuthenticationHandler
        extends AbstractJdbcUsernamePasswordAuthenticationHandler {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    public HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credentials) throws FailedLoginException {
        String username = credentials.getUsername();
        String password = credentials.getPassword();


        password = Md5ConverterUtil.Md5(password);
        Object[] args = new Object[] { username };
        String sql = "select GM_USER_ID,LOGIN,PASSWORD,NAME,TYPE,GM_COMPANY_ID from gm_user where state='1' and login=? ";
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
                String credPwd = credentials.getPassword();
                credPwd = new String(Base64.decode(credPwd));
                pwd = AESUtil.decrypt(credPwd,gmCompanyId);
                pwd = Md5ConverterUtil.Md5(pwd);
                if(pwd.equals(user.get("PASSWORD"))){
                    return createHandlerResult(credentials,
                            this.principalFactory.createPrincipal(username), null);
                }
            } catch (Exception e) {
                logger.error("密码解析异常：{}",e);
            }
            throw new FailedLoginException("Multiple records found for " + username);
        }
        return createHandlerResult(credentials,
                this.principalFactory.createPrincipal(username), null);
    }


}
