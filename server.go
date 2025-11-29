package main

import (
	"context"
	"log"
	"net/http"

	"zurvan-api/config"
	"zurvan-api/database"
	"zurvan-api/feature/auth/application/usecases"
	"zurvan-api/feature/auth/infrastructure/repositories"
	"zurvan-api/graph"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/vektah/gqlparser/v2/ast"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Setup database connection
	database.InitPostgresClient(cfg.Database)

	// Setup repositories
	userRepo := repositories.NewPostgresUserRepository(database.PostgresClient())
	emailVerificationRepo := repositories.NewPostgresEmailVerificationRepository(database.PostgresClient())

	// Setup use cases
	authUseCase := usecases.NewAuthUseCase(
		userRepo,
		emailVerificationRepo,
		[]byte(cfg.JWT.Secret),
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
	)

	// Setup GraphQL server
	resolver := &graph.Resolver{
		AuthUseCase: authUseCase,
	}

	srv := handler.New(graph.NewExecutableSchema(graph.Config{Resolvers: resolver}))

	// Configure transport
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})

	// Configure cache
	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

	// Add extensions
	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})

	// Setup HTTP handlers
	http.Handle("/", playground.Handler("GraphQL playground", "/query"))

	// Wrap GraphQL handler with middleware to inject request into context
	http.Handle("/query", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create new context with the HTTP request
		ctx := context.WithValue(r.Context(), "request", r)
		r = r.WithContext(ctx)

		srv.ServeHTTP(w, r)
	}))

	go runMigrations(cfg.Database)

	log.Printf("🚀 Server ready at http://localhost:%s/", cfg.Port)
	log.Printf("📊 GraphQL playground at http://localhost:%s/", cfg.Port)
	log.Printf("🔍 GraphQL endpoint at http://localhost:%s/query", cfg.Port)

	log.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}

func runMigrations(dbCfg config.DatabaseConfig) {
	connectionURL := dbCfg.ConnectionURL
	if connectionURL == "" {
		log.Fatal("POSTGRES_CONNECTION_URL is not set in environment variables")
	}

	migrator, err := database.NewMigrator(connectionURL)
	if err != nil {
		log.Fatalf("Failed to initialize migrator: %v", err)
	}

	now, exp, info, err := migrator.Info()
	if err != nil {
		log.Fatalf("Failed to get migration info: %v", err)
	}

	log.Printf("Current DB Version: %d, Latest Version: %d\nMigration Info:\n%s", now, exp, info)

	if now < exp {
		log.Printf("Running migrations...")
		if err := migrator.Migrate(); err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
		log.Printf("Migration completed successfully to %v. \n", exp)
	} else {
		log.Printf("No migrations needed.")
	}
}
