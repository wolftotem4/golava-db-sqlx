package sqlx

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/wolftotem4/golava-core/auth"
	"github.com/wolftotem4/golava-core/hashing"
)

type SqlxUserProvider struct {
	DB            *sqlx.DB
	Hasher        hashing.Hasher
	Table         string
	ConstructUser func() auth.Authenticatable
}

func (p *SqlxUserProvider) RetrieveById(ctx context.Context, identifier any) (auth.Authenticatable, error) {
	user := p.ConstructUser()
	query := p.DB.Rebind(fmt.Sprintf("SELECT * FROM %s WHERE id = ?", p.Table))
	err := p.DB.GetContext(ctx, user, query, identifier)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrUserNotFound
	}
	return user, err
}

func (p *SqlxUserProvider) RetrieveByToken(ctx context.Context, identifier any, token string) (auth.Authenticatable, error) {
	user := p.ConstructUser()
	query := p.DB.Rebind(fmt.Sprintf("SELECT * FROM %s WHERE id = ?", p.Table))
	err := p.DB.GetContext(ctx, user, query, identifier)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(user.GetRememberToken())) != 1 {
		return nil, auth.ErrUserNotFound
	}

	return user, nil
}

func (p *SqlxUserProvider) UpdateRememberToken(ctx context.Context, user auth.Authenticatable, token string) error {
	query := p.DB.Rebind(fmt.Sprintf(
		"UPDATE %s SET %s = ? WHERE %s = ?",
		p.Table,
		user.GetRememberTokenName(),
		user.GetAuthIdentifierName(),
	))

	_, err := p.DB.ExecContext(
		ctx,
		query,
		token,
		user.GetAuthIdentifier(),
	)
	return err
}

func (p *SqlxUserProvider) RetrieveByCredentials(ctx context.Context, credentials map[string]any) (auth.Authenticatable, error) {
	var (
		wheres = make([]string, 0, len(credentials))
		values = make([]any, 0, len(credentials))
	)

	for key, value := range credentials {
		if strings.Contains(key, "password") {
			continue
		}

		wheres = append(wheres, fmt.Sprintf("%s = ?", key))
		values = append(values, value)
	}

	if len(wheres) == 0 {
		return nil, auth.ErrUserNotFound
	}

	query := p.DB.Rebind(fmt.Sprintf("SELECT * FROM %s WHERE %s", p.Table, strings.Join(wheres, " AND ")))

	var user = p.ConstructUser()
	err := p.DB.GetContext(ctx, user, query, values...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrUserNotFound
	}

	return user, err
}

func (p *SqlxUserProvider) ValidateCredentials(ctx context.Context, user auth.Authenticatable, credentials map[string]any) (bool, error) {
	password, ok := credentials[user.GetAuthPasswordName()]
	if !ok {
		return false, nil
	}

	return p.Hasher.Check(password.(string), user.GetAuthPassword())
}

func (p *SqlxUserProvider) RehashPasswordIfRequired(ctx context.Context, user auth.Authenticatable, credentials map[string]any, force bool) error {
	if !p.Hasher.NeedsRehash(user.GetAuthPassword()) && !force {
		return nil
	}

	hash, err := p.Hasher.Make(credentials[user.GetAuthPasswordName()].(string))
	if err != nil {
		return err
	}

	query := p.DB.Rebind(fmt.Sprintf(
		"UPDATE %s SET %s = ? WHERE %s = ?",
		p.Table,
		user.GetAuthPasswordName(),
		user.GetAuthIdentifierName(),
	))

	_, err = p.DB.ExecContext(
		ctx,
		query,
		hash,
		user.GetAuthIdentifier(),
	)
	return err
}
