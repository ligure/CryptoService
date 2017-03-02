package com.ligure.crypto.servlet;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jackson.map.ObjectMapper;

import com.ligure.crypto.util.CryptUtil;

@WebServlet("/decrypt")
public class Decrypt extends HttpServlet {

    private static final long serialVersionUID = 3585346897997303225L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public Decrypt() {
	super();
    }

    /**
     * @throws IOException
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request,
	    HttpServletResponse response) throws IOException {
	doPost(request, response);
    }

    /**
     * @throws IOException
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest request,
	    HttpServletResponse response) throws IOException {
	String name = request.getParameter("name");
	String mode = request.getParameter("mode");
	String key = request.getParameter("key");
	String data = request.getParameter("data");
	String code = "0", msg = "请求成功";
	if (null == data) {
	    code = "1001";
	    msg = "缺少请求参数data";
	} else if (null == key) {
	    code = "1002";
	    msg = "缺少请求参数key";
	} else {
	    int klen = key.getBytes("utf-8").length;
	    if (CryptUtil.DES.equalsIgnoreCase(name)) {
		name = CryptUtil.DES;
		if (klen != 8) {
		    code = "1003";
		    msg = "请求参数key的长度不满足要求，DES算法要求KEY的长度为8个字节";
		}
	    } else if (CryptUtil.DESEDE.equalsIgnoreCase(name)) {
		name = CryptUtil.DESEDE;
		if (klen != 24) {
		    code = "1004";
		    msg = "请求参数key的长度不满足要求，DESede算法要求KEY的长度为24个字节";
		}
	    } else if (CryptUtil.AES.equalsIgnoreCase(name)) {
		name = CryptUtil.AES;
		if (klen != 16) {
		    code = "1005";
		    msg = "请求参数key的长度不满足要求，AES算法要求KEY的长度为16个字节";
		}
	    } else if (CryptUtil.BLOWFISH.equalsIgnoreCase(name)) {
		name = CryptUtil.BLOWFISH;
		if (klen < 1 || klen > 16) {
		    code = "1005";
		    msg = "请求参数key的长度不满足要求，BlowFish算法要求KEY的长度为1-16个字节";
		}
	    } else {
		name = CryptUtil.DES;
		msg = "未提供请求参数name，默认使用DES算法进行解密";
		if (klen != 8) {
		    code = "1006";
		    msg += "，请求参数key的长度不满足KEY的长度为8个字节的要求";
		}
	    }
	}
	if ("0".equals(code)) {
	    data = CryptUtil.decrypt(data, key, name, mode);
	} else {
	    data = "";
	}
	response.setContentType("application/json;charset=utf-8");
	Writer w = response.getWriter();
	Map<String, Object> outMap = new HashMap<>();
	outMap.put("data", data);
	outMap.put("msg", msg);
	outMap.put("code", code);
	ObjectMapper mapper = new ObjectMapper();
	mapper.writeValue(w, outMap);
	w.flush();
	w.close();
    }

}
