package com.ligure.crypto.servlet;

import java.io.IOException;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jackson.map.ObjectMapper;

import com.ligure.crypto.util.CryptUtil;

@WebServlet("/md5")
public class MD5 extends HttpServlet {

    private static final long serialVersionUID = 3585346897997303225L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public MD5() {
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
	String code = "0", msg = "请求成功";
	String data = request.getParameter("data");
	if (null == data) {
	    code = "1001";
	    msg = "缺少请求参数data";
	}
	if ("0".equals(code)) {
	    data = CryptUtil.getMD5(URLDecoder.decode(data, "utf-8"));
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
