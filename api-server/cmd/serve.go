package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tianweidut/cron"
	"gopkg.in/yaml.v3"

	"github.com/bentoml/yatai/api-server/config"
	"github.com/bentoml/yatai/api-server/routes"
	"github.com/bentoml/yatai/api-server/services"
	"github.com/bentoml/yatai/api-server/services/tracking"
	"github.com/bentoml/yatai/common/command"
	"github.com/bentoml/yatai/common/sync/errsgroup"
)

func generateHashedPassword(rawPassword string) ([]byte, error) {
	if len(rawPassword) == 0 {
		return []byte(""), nil
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), 8)
	if err != nil {
		return nil, errors.New("generate hashed password")
	}
	return hashedPassword, nil
}

func addCron(ctx context.Context) {
	c := cron.New()
	logger := logrus.New().WithField("cron", "sync env")

	// Add cron for tracking lifecycle events
	tracking.AddLifeCycleTrackingCron(ctx, c)

	err := c.AddFunc("@every 1m", func() {
		ctx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		logger.Info("listing unsynced deployments")
		deployments, err := services.DeploymentService.ListUnsynced(ctx)
		if err != nil {
			logger.Errorf("list unsynced deployments: %s", err.Error())
		}
		logger.Info("updating unsynced deployments syncing_at")
		now := time.Now()
		nowPtr := &now
		for _, deployment := range deployments {
			_, err := services.DeploymentService.UpdateStatus(ctx, deployment, services.UpdateDeploymentStatusOption{
				SyncingAt: &nowPtr,
			})
			if err != nil {
				logger.Errorf("update deployment %d status: %s", deployment.ID, err.Error())
			}
		}
		logger.Info("updated unsynced deployments syncing_at")
		var eg errsgroup.Group
		eg.SetPoolSize(1000)
		for _, deployment := range deployments {
			deployment := deployment
			eg.Go(func() error {
				_, err := services.DeploymentService.SyncStatus(ctx, deployment)
				return err
			})
		}

		logger.Info("syncing unsynced app deployment deployments...")
		err = eg.WaitWithTimeout(10 * time.Minute)
		logger.Info("synced unsynced app deployment deployments...")
		if err != nil {
			logger.Errorf("sync deployments: %s", err.Error())
		}
	})

	if err != nil {
		logger.Errorf("cron add func failed: %s", err.Error())
	}

	c.Start()
}

type ServeOption struct {
	ConfigPath string
}

func (opt *ServeOption) Validate(ctx context.Context) error {
	return nil
}

func (opt *ServeOption) Complete(ctx context.Context, args []string, argsLenAtDash int) error {
	return nil
}

func initSelfHost(ctx context.Context) error {
	defaultOrg, err := services.OrganizationService.GetDefault(ctx)
	if err != nil {
		return errors.Wrap(err, "get default org")
	}

	_, err = services.ClusterService.GetDefault(ctx, defaultOrg.ID)

	return err
}

func (opt *ServeOption) Run(ctx context.Context, args []string) error {
	if !command.GlobalCommandOption.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	content, err := os.ReadFile(opt.ConfigPath)
	if err != nil {
		return errors.Wrapf(err, "read config file: %s", opt.ConfigPath)
	}

	err = yaml.Unmarshal(content, config.YataiConfig)
	if err != nil {
		return errors.Wrapf(err, "unmarshal config file: %s", opt.ConfigPath)
	}

	err = config.PopulateYataiConfig()
	if err != nil {
		return errors.Wrapf(err, "populate config file: %s", opt.ConfigPath)
	}

	err = services.MigrateUp()
	if err != nil {
		return errors.Wrap(err, "migrate up db")
	}

	if !config.YataiConfig.IsSaaS {
		err = initSelfHost(ctx)
		if err != nil {
			return errors.Wrap(err, "init self host")
		}
	}

	addCron(ctx)

	// nolint: contextcheck
	router, err := routes.NewRouter()
	if err != nil {
		return err
	}

	readHeaderTimeout := 10 * time.Second
	if config.YataiConfig.Server.ReadHeaderTimeout > 0 {
		readHeaderTimeout = time.Duration(config.YataiConfig.Server.ReadHeaderTimeout) * time.Second
	}

	logrus.Infof("listening on 0.0.0.0:%d", config.YataiConfig.Server.Port)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.YataiConfig.Server.Port),
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	// create user
	pg_user := os.Getenv("PG_USER")
	pg_host := os.Getenv("PG_HOST")
	pg_port := os.Getenv("PG_PORT")
	pg_password := os.Getenv("PG_PASSWORD")
	pg_dbname := os.Getenv("PG_DATABASE")
	var count int
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=disable", pg_user, pg_password, pg_host, pg_port, pg_dbname)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return errors.Wrap(err, "Create user")
	}
	defer db.Close()
	err = db.QueryRow("SELECT COUNT(*) FROM user").Scan(&count)
	if err != nil {
		return errors.Wrap(err, "create user")
	}
	if count != 0 {
		name := os.Getenv("USERNAME")
		email := os.Getenv("EMAIL")
		password := os.Getenv("PASSWORD")
		hashed_password, err := generateHashedPassword(password)
		date := "2023-01-01 00:00:00.000 +0000"
		uid := "onyxia"
		scopes := [...]string{"api", "read_organization", "write_organization", "read_cluster", "write_cluster"}

		user_stmt, err := db.Prepare("INSERT INTO user(id, uid, perm, name, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
		if err != nil {
			return errors.Wrap(err, "Create user")
		}
		defer user_stmt.Close()

		cluster_member_stmt, err := db.Prepare("INSERT INTO cluster_member(id, uid, cluster_id, user_id, role, creator_id, created_at, updated_at ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
		if err != nil {
			return errors.Wrap(err, "Create user")
		}
		defer cluster_member_stmt.Close()

		organization_member_stmt, err := db.Prepare("INSERT INTO organization_member(id, uid, organization_id, user_id, role, creator_id, created_at, updated_at ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
		if err != nil {
			return errors.Wrap(err, "Create user")
		}
		defer user_stmt.Close()

		api_token_stmt, err := db.Prepare("INSERT INTO api_token(id, uid, name, token, scopes, organization_id, user_id, created_at, updated_at ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
		if err != nil {
			return errors.Wrap(err, "Create token")
		}
		defer user_stmt.Close()

		_, err = user_stmt.Exec(1, uid, "admin", name, email, string(hashed_password), date, date)
		if err != nil {
			return errors.Wrap(err, "Create user")
		}
		_, err = cluster_member_stmt.Exec(1, uid, 1, 1, "admin", 1, date, date)
		if err != nil {
			return errors.Wrap(err, "Create user")
		}

		_, err = organization_member_stmt.Exec(1, uid, 1, 1, "admin", 1, date, date)
		if err != nil {
			return errors.Wrap(err, "Create user")
		}

		_, err = api_token_stmt.Exec(1, uid, "token", password, scopes, 1, 1, date, date)
		if err != nil {
			return errors.Wrap(err, "Create token")
		}
	}

	return srv.ListenAndServe()
}

func getServeCmd() *cobra.Command {
	var opt ServeOption
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "run yatai api server",
		Long:  "",
		RunE:  command.MakeRunE(&opt),
	}
	cmd.Flags().StringVarP(&opt.ConfigPath, "config", "c", "./yatai-config.dev.yaml", "")
	return cmd
}
