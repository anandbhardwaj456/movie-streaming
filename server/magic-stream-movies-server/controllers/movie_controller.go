package controllers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	database "github.com/anandbhardwaj456/movie-streaming/tree/main/server/magic-stream-movies-server/database"
	models "github.com/anandbhardwaj456/movie-streaming/tree/main/server/magic-stream-movies-server/models"
	utils "github.com/anandbhardwaj456/movie-streaming/tree/main/server/magic-stream-movies-server/utils"
	"github.com/tmc/langchaingo/llms/openai"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var validate = validator.New()

func GetMovies(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		var movies []models.Movie
		var moviesCollection *mongo.Collection = database.OpenCollection("movies", client)
		cursor, err := moviesCollection.Find(ctx, bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch movies."})
			return
		}
		defer cursor.Close(ctx)

		if err := cursor.All(ctx, &movies); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode movies."})
			return
		}
		c.JSON(http.StatusOK, movies)
	}
}

func GetMovie(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		movieID := c.Param("imdb_id")
		if movieID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Movie ID is required"})
			return
		}

		var movie models.Movie
		var moviesCollection *mongo.Collection = database.OpenCollection("movies", client)
		err := moviesCollection.FindOne(ctx, bson.M{"imdb_id": movieID}).Decode(&movie)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Movie not found"})
			return
		}
		c.JSON(http.StatusOK, movie)
	}
}

func AddMovie(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		var movie models.Movie
		if err := c.ShouldBindJSON(&movie); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		if err := validate.Struct(movie); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": err.Error()})
			return
		}

		var moviesCollection *mongo.Collection = database.OpenCollection("movies", client)
		result, err := moviesCollection.InsertOne(ctx, movie)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add movie"})
			return
		}
		c.JSON(http.StatusCreated, result)
	}
}

func AdminReviewUpdate(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		role, err := utils.GetRoleFromContext(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "role not found in context"})
			return
		}
		if role != "ADMIN" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User must be the part of the ADMIN role"})
			return
		}

		movieID := c.Param("imdb_id")
		if movieID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Movie ID is required"})
			return
		}

		var request struct {
			AdminReview string `json:"admin_review"`
		}
		var response struct {
			RankingName string `json:"ranking_name"`
			AdminReview string `json:"admin_review"`
		}

		if err := c.ShouldBind(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		sentiment, rankingValue, err := GetReviewRanking(c, request.AdminReview, client)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting review ranking"})
			return
		}

		filter := bson.M{"imbdb_id": movieID}
		update := bson.M{
			"$set": bson.M{
				"admin_review": request.AdminReview,
				"ranking": bson.M{
					"ranking_value": rankingValue,
					"ranking_name":  sentiment,
				},
			},
		}
		var moviesCollection *mongo.Collection = database.OpenCollection("movies", client)
		result, err := moviesCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating movie"})
			return
		}
		if result.MatchedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Movie not found"})
			return
		}

		response.RankingName = sentiment
		response.AdminReview = request.AdminReview
		c.JSON(http.StatusOK, response)
	}
}

func GetReviewRanking(c *gin.Context, adminReview string, client *mongo.Client) (string, int, error) {
	rankings, err := GetRankings(c, client)
	if err != nil {
		return "", 0, err
	}

	sentimentDelimited := ""
	for _, ranking := range rankings {
		if ranking.RankingValue != 999 {
			sentimentDelimited = sentimentDelimited + ranking.RankingName + ","
		}
	}
	sentimentDelimited = strings.Trim(sentimentDelimited, ",")

	if err := godotenv.Load(".env"); err != nil {
		log.Println("Warning: .env file not found")
	}

	OpenAIAPIKey := os.Getenv("OPENAI_API_KEY")
	if OpenAIAPIKey == "" {
		return "", 0, errors.New("Could not read OPENAI_API_KEY")
	}

	llm, err := openai.New(openai.WithToken(OpenAIAPIKey))
	if err != nil {
		return "", 0, err
	}

	basePromptTemplate := os.Getenv("BASE_PROMPT_TEMPLATE")
	basePrompt := strings.Replace(basePromptTemplate, "{rankings}", sentimentDelimited, 1)

	response, err := llm.Call(context.Background(), basePrompt+adminReview)
	if err != nil {
		return "", 0, err
	}

	rankingValue := 0
	for _, ranking := range rankings {
		if ranking.RankingName == response {
			rankingValue = ranking.RankingValue
			break
		}
	}
	return response, rankingValue, nil
}

func GetRankings(c *gin.Context, client *mongo.Client) ([]models.Ranking, error) {
	var rankings []models.Ranking

	ctx, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()

	var rankingsCollection *mongo.Collection = database.OpenCollection("rankings", client)
	cursor, err := rankingsCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &rankings); err != nil {
		return nil, err
	}

	return rankings, nil
}

func GetRecommendedMovies(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		userID, err := utils.GetUserIDFromContext(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found in context"})
			return
		}

		favouriteGenres, err := GetUserFavouriteGenres(c, userID, client)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := godotenv.Load(".env"); err != nil {
			log.Println("Warning: .env file not found")
		}

		var recommendedMoviesLimitValue int64 = 5
		recommendedMoviesLimitString := os.Getenv("RECOMMENDED_MOVIE_LIMIT")
		if recommendedMoviesLimitString != "" {
			recommendedMoviesLimitValue, _ = strconv.ParseInt(recommendedMoviesLimitString, 10, 64)
		}

		filter := bson.M{"genre.genre_name": bson.M{"$in": favouriteGenres}}
		findOptions := options.Find()
		findOptions.SetSort(bson.D{{Key: "ranking.ranking_value", Value: 1}})
		findOptions.SetLimit(recommendedMoviesLimitValue)
		var moviesCollection *mongo.Collection = database.OpenCollection("movies", client)
		cursor, err := moviesCollection.Find(ctx, filter, findOptions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching recommended movies"})
			return
		}
		defer cursor.Close(ctx)

		var recommendedMovies []models.Movie
		if err := cursor.All(ctx, &recommendedMovies); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, recommendedMovies)
	}
}

func GetUserFavouriteGenres(c *gin.Context, userID string, client *mongo.Client) ([]string, error) {
	ctx, cancel := context.WithTimeout(c, 100*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID}

	projection := bson.M{
		"favourite_genres.genre_name": 1,
		"_id":                         0,
	}
	options := options.FindOne().SetProjection(projection)

	var results bson.M
	var usersCollection *mongo.Collection = database.OpenCollection("users", client)
	err := usersCollection.FindOne(ctx, filter, options).Decode(&results)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return []string{}, nil
		}
	}

	favouriteGenresArray, ok := results["favourite_genres"].(bson.A)
	if !ok {
		return []string{}, errors.New("Unable to retrieve favourite genres for user")
	}

	var genreNames []string
	for _, item := range favouriteGenresArray {
		if genreMap, ok := item.(bson.D); ok {
			for _, element := range genreMap {
				if element.Key == "genre_name" {
					if name, ok := element.Value.(string); ok {
						genreNames = append(genreNames, name)
					}
				}
			}
		}
	}
	return genreNames, nil
}

func GetGenres(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 100*time.Second)
		defer cancel()

		var genres []models.Genre
		var genresCollection *mongo.Collection = database.OpenCollection("genres", client)
		cursor, err := genresCollection.Find(ctx, bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching movie genres"})
			return
		}
		defer cursor.Close(ctx)

		if err := cursor.All(ctx, &genres); err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, genres)
	}
}
