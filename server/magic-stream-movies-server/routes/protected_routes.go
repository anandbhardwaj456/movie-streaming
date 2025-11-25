package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/raghuvansh-sahil/magic-stream-movies/server/magic-stream-movies-server/controllers"
	middleware "github.com/raghuvansh-sahil/magic-stream-movies/server/magic-stream-movies-server/middleware"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func SetupProtectedRoutes(router *gin.Engine, client *mongo.Client) {
	router.Use(middleware.AuthMiddleware())

	router.GET("/movie/:imdb_id", controllers.GetMovie(client))
	router.POST("/addmovie", controllers.AddMovie(client))
	router.PATCH("/updatereview/:imdb_id", controllers.AdminReviewUpdate(client))
	router.GET("/recommendedmovies", controllers.GetRecommendedMovies(client))
}
