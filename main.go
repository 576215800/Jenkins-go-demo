package main

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"net/http"
	"time"
)

type jwtCustomClaims struct {
	Name string `json:"name"`
	//Password string `json:"Password"`
	Admin bool `json:"admin"`
	jwt.StandardClaims
}
type User struct {
	Username string
	Password string
}

func main() {
	//实例化echo对象。
	e := echo.New()

	//Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	//Login route
	e.POST("/login", login)

	//Unauthenticated route  沒有限制的路徑
	e.GET("/", accessible)
	e.GET("/hello", sayHello)
	// Restricted group		 帶有限制的路徑
	r := e.Group("/restricted")
	//Configure  middleware with custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}
	r.Use(middleware.JWTWithConfig(config))
	r.GET("", restricted)
	//注册一个Get请求, 路由地址为: /tizi365  并且绑定一个控制器函数, 这里使用的是闭包函数。
	e.GET("/tizi365", func(c echo.Context) error {
		//控制器函数直接返回一个字符串，http响应状态为http.StatusOK，就是200状态。
		return c.String(http.StatusOK, "欢迎访问tizi365.com")
	})

	//启动http server, 并监听8082端口，冒号（:）前面为空的意思就是绑定网卡所有Ip地址，本机支持的所有ip地址都可以访问。
	e.Logger.Fatal(e.Start(":8082"))
}

//登录会生成一个token返回给用户, 下一次用户登录的时候通过请求头携带这个token登录
func login(c echo.Context) error {
	u := new(User)
	err := c.Bind(u)
	if err != nil {
		return err
	}
	if u.Username == "denghao" && u.Password == "123456" {
		//set custom claims
		claims := &jwtCustomClaims{
			"denghao",
			true,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			},
		}
		//Create token with claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		//Generate encoded  token  and send it as response
		t, err := token.SignedString([]byte("secret"))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, echo.Map{
			"token": t,
		})
	}
	return echo.ErrUnauthorized
}
func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

//只要请求中携带字符能够被解析,则通过了JWT
func restricted(c echo.Context) error {

	user := c.Get("user").(*jwt.Token)
	fmt.Println("-------------------------------")
	fmt.Println(user)
	fmt.Println("-------------------------------")
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name
	return c.String(http.StatusOK, "Welcome "+name+"!")
}
func sayHello(c echo.Context) error {
	return c.String(http.StatusOK, "hello world!")
}
