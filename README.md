# Diary API

## Introduction
This project provides an API for a personal diary app with features including registration, login, creating new diary entries, and retrieving all diary entries.

## Prerequisites
Before getting started, ensure you have the following:
- Basic understanding of Go and JWTs
- curl
- Git
- Go 1.19 or later
- PostgreSQL installed on your machine

## Getting Started
1. Create a new folder for the project:
    ```bash
    mkdir diary_api
    cd diary_api
    ```

2. Initialize a Go module:
    ```bash
    go mod init diary_api
    ```

3. Install project dependencies:
    ```bash
    go get \
        github.com/gin-gonic/gin \
        github.com/golang-jwt/jwt/v4 \
        github.com/joho/godotenv \
        golang.org/x/crypto \
        gorm.io/driver/postgres \
        gorm.io/gorm
    ```

4. Create a PostgreSQL database named `diary_app`:
    ```bash
    createdb -h <DB_HOSTNAME> -p <DB_PORT> -U <DB_USER> diary_app --password
    ```

5. Create a `.env` file in the project root with the following content:
    ```ini
    # Database credentials
    DB_HOST="<<DB_HOST>>"
    DB_USER="<<DB_USER>>"
    DB_PASSWORD="<<DB_PASSWORD>>"
    DB_NAME="diary_app"
    DB_PORT="<<DB_PORT>>"

    # Authentication credentials
    TOKEN_TTL="2000"
    JWT_PRIVATE_KEY="THIS_IS_NOT_SO_SECRET+YOU_SHOULD_DEFINITELY_CHANGE_IT"
    ```

6. Make a copy of `.env` named `.env.local`:
    ```bash
    cp .env .env.local
    ```

7. Replace placeholder values in `.env.local` with your database details.

## Models
The project includes two models: User and Entry. These models define the structure of the database tables.

Next, you'll create the two models for the application: User and Entry. To do this, start by creating a new folder named model. In that directory, create a new file named user.go, and then add the following code to the newly created file.

```go
package model

import "gorm.io/gorm"

type User struct {
    gorm.Model
    Username string `gorm:"size:255;not null;unique" json:"username"`
    Password string `gorm:"size:255;not null;" json:"-"`
    Entries  []Entry
}
```
Next, create a new file named entry.go and add the following code to it.
```Go
package model

import "gorm.io/gorm"

type Entry struct {
    gorm.Model
    Content string `gorm:"type:text" json:"content"`
    UserID  uint
}
```

## Database Setup
A helper function is provided to connect to the PostgreSQL database using GORM.

With the models in place, create a helper function to connect to the database, by creating a new folder named database, and in it a new file named database.go. Then, add the following code to the new file.

```Go
package database

import (
    "fmt"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "os"
)

var Database *gorm.DB

func Connect() {
    var err error
    host := os.Getenv("DB_HOST")
    username := os.Getenv("DB_USER")
    password := os.Getenv("DB_PASSWORD")
    databaseName := os.Getenv("DB_NAME")
    port := os.Getenv("DB_PORT")

    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Africa/Lagos", host, username, password, databaseName, port)
    Database, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

    if err != nil {
        panic(err)
    } else {
        fmt.Println("Successfully connected to the database")
    }
}
```

## Authentication
Endpoints for user registration and login are implemented using JWT for authentication.

Next, create a new folder named helper. In this folder, create a new file named jwt.go. In it, add the following code.
```Go
package helper

import (
    "diary_api/model"
    "github.com/golang-jwt/jwt/v4"
    "os"
    "strconv"
    "time"
)

var privateKey = []byte(os.Getenv("JWT_PRIVATE_KEY"))

func GenerateJWT(user model.User) (string, error) {
    tokenTTL, _ := strconv.Atoi(os.Getenv("TOKEN_TTL"))
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "id":  user.ID,
        "iat": time.Now().Unix(),
        "eat": time.Now().Add(time.Second * time.Duration(tokenTTL)).Unix(),
    })
    return token.SignedString(privateKey)
}
```
This function takes a user model and generates a JWT containing the user’s id (id), the time at which the token was issued (iat), and the expiry date of the token (eat). Using the JWT_PRIVATE_KEY environment variable, a signed JWT is returned as a string.

Next, in controller/authentication.go, add the following function.
```Go
func Login(context *gin.Context) {
    var input model.AuthenticationInput

    if err := context.ShouldBindJSON(&input); err != nil {
        context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    user, err := model.FindUserByUsername(input.Username)

    if err != nil {
        context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err = user.ValidatePassword(input.Password)

    if err != nil {
        context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    jwt, err := helper.GenerateJWT(user)
    if err != nil {
        context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    context.JSON(http.StatusOK, gin.H{"jwt": jwt})
} 
```

## Adding a New Entry
Endpoints are provided to add a new diary entry and retrieve all entries for the authenticated user.

Before declaring the route or controller for this endpoint, add a method to the Entry struct which will allow you to save a new entry. In the model/entry.go file, add the following code.

```Go
func (entry *Entry) Save() (*Entry, error) {
    err := database.Database.Create(&entry).Error
    if err != nil {
        return &Entry{}, err
    }
    return entry, nil
}
```

## Middleware
Middleware is implemented to handle requests to authenticated endpoints, ensuring a valid JWT is present.

The next endpoints you will implement require that the user be authenticated. In other words, requests to these endpoints will require a bearer token in the request header. If none is found, an error response should be returned.

To do this, you will implement middleware. This middleware will intercept requests and ensure that a valid bearer token is present in the request before the appropriate handler is called.

Before building the middleware, you’ll need to add some helper functions to make the process of extracting and validating JWTs easier. Add the following functions to helper/jwt.go.

```Go
func ValidateJWT(context *gin.Context) error {
    token, err := getToken(context)
    if err != nil {
        return err
    }
    _, ok := token.Claims.(jwt.MapClaims)
    if ok && token.Valid {
        return nil
    }
    return errors.New("invalid token provided")
}

func CurrentUser(context *gin.Context) (model.User, error) {
    err := ValidateJWT(context)
    if err != nil {
        return model.User{}, err
    }
    token, _ := getToken(context)
    claims, _ := token.Claims.(jwt.MapClaims)
    userId := uint(claims["id"].(float64))

    user, err := model.FindUserById(userId)
    if err != nil {
        return model.User{}, err
    }
    return user, nil
}

func getToken(context *gin.Context) (*jwt.Token, error) {
    tokenString := getTokenFromRequest(context)
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        return privateKey, nil
    })
    return token, err
}

func getTokenFromRequest(context *gin.Context) string {
    bearerToken := context.Request.Header.Get("Authorization")
    splitToken := strings.Split(bearerToken, " ")
    if len(splitToken) == 2 {
        return splitToken[1]
    }
    return ""
}
```

## Usage
1. Start the application:
    ```bash
    go run main.go
    ```

2. Register a new user:
    ```bash
    curl -i -H "Content-Type: application/json" \
        -X POST \
        -d '{"username":"<<USERNAME>>", "password":"<<PASSWORD>>"}' \
        http://localhost:8000/auth/register
    ```

3. Login:
    ```bash
    curl -i -H "Content-Type: application/json" \
        -X POST \
        -d '{"username":"<<USERNAME>>", "password":"<<PASSWORD>>"}' \
        http://localhost:8000/auth/login
    ```

4. Use the JWT returned to make authenticated requests to add new entries and retrieve all entries.

## Conclusion
You now have a functional diary API ready for use!