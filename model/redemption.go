package model

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"

	"gorm.io/gorm"
)

// ErrRedeemFailed is returned when redemption fails due to database error
var ErrRedeemFailed = errors.New("redeem.failed")

const (
	RedemptionTypeQuota        = "quota"
	RedemptionTypeSubscription = "subscription"
)

func NormalizeRedemptionType(v string) string {
	switch strings.TrimSpace(v) {
	case RedemptionTypeSubscription:
		return RedemptionTypeSubscription
	default:
		return RedemptionTypeQuota
	}
}

type Redemption struct {
	Id                    int            `json:"id"`
	UserId                int            `json:"user_id"`
	Key                   string         `json:"key" gorm:"type:char(32);uniqueIndex"`
	Status                int            `json:"status" gorm:"default:1"`
	Name                  string         `json:"name" gorm:"index"`
	Quota                 int            `json:"quota" gorm:"default:100"`
	RedemptionType        string         `json:"redemption_type" gorm:"type:varchar(32);not null;default:'quota'"`
	SubscriptionPlanId    int            `json:"subscription_plan_id" gorm:"index;default:0"`
	SubscriptionPlanTitle string         `json:"subscription_plan_title" gorm:"-:all"`
	CreatedTime           int64          `json:"created_time" gorm:"bigint"`
	RedeemedTime          int64          `json:"redeemed_time" gorm:"bigint"`
	Count                 int            `json:"count" gorm:"-:all"` // only for api request
	UsedUserId            int            `json:"used_user_id"`
	DeletedAt             gorm.DeletedAt `gorm:"index"`
	ExpiredTime           int64          `json:"expired_time" gorm:"bigint"` // 过期时间，0 表示不过期
}

type RedeemResult struct {
	RedemptionType        string `json:"redemption_type"`
	Quota                 int    `json:"quota"`
	SubscriptionPlanId    int    `json:"subscription_plan_id,omitempty"`
	SubscriptionPlanTitle string `json:"subscription_plan_title,omitempty"`
	UserSubscriptionId    int    `json:"user_subscription_id,omitempty"`
}

func GetAllRedemptions(startIdx int, num int) (redemptions []*Redemption, total int64, err error) {
	// 开始事务
	tx := DB.Begin()
	if tx.Error != nil {
		return nil, 0, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 获取总数
	err = tx.Model(&Redemption{}).Count(&total).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// 获取分页数据
	err = tx.Order("id desc").Limit(num).Offset(startIdx).Find(&redemptions).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}
	if err = attachRedemptionPlanTitles(redemptions); err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// 提交事务
	if err = tx.Commit().Error; err != nil {
		return nil, 0, err
	}

	return redemptions, total, nil
}

func SearchRedemptions(keyword string, startIdx int, num int) (redemptions []*Redemption, total int64, err error) {
	tx := DB.Begin()
	if tx.Error != nil {
		return nil, 0, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Build query based on keyword type
	query := tx.Model(&Redemption{})

	// Only try to convert to ID if the string represents a valid integer
	if id, err := strconv.Atoi(keyword); err == nil {
		query = query.Where("id = ? OR name LIKE ?", id, keyword+"%")
	} else {
		query = query.Where("name LIKE ?", keyword+"%")
	}

	// Get total count
	err = query.Count(&total).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// Get paginated data
	err = query.Order("id desc").Limit(num).Offset(startIdx).Find(&redemptions).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}
	if err = attachRedemptionPlanTitles(redemptions); err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	if err = tx.Commit().Error; err != nil {
		return nil, 0, err
	}

	return redemptions, total, nil
}

func GetRedemptionById(id int) (*Redemption, error) {
	if id == 0 {
		return nil, errors.New("id 为空！")
	}
	redemption := Redemption{Id: id}
	var err error = nil
	err = DB.First(&redemption, "id = ?", id).Error
	if err == nil {
		err = attachRedemptionPlanTitle(&redemption)
	}
	return &redemption, err
}

func Redeem(key string, userId int) (result *RedeemResult, err error) {
	if key == "" {
		return nil, errors.New("未提供兑换码")
	}
	if userId == 0 {
		return nil, errors.New("无效的 user id")
	}
	redemption := &Redemption{}
	redeemResult := &RedeemResult{}
	upgradeGroup := ""

	keyCol := "`key`"
	if common.UsingPostgreSQL {
		keyCol = `"key"`
	}
	common.RandomSleep()
	err = DB.Transaction(func(tx *gorm.DB) error {
		err := tx.Set("gorm:query_option", "FOR UPDATE").Where(keyCol+" = ?", key).First(redemption).Error
		if err != nil {
			return errors.New("无效的兑换码")
		}
		if redemption.Status != common.RedemptionCodeStatusEnabled {
			return errors.New("该兑换码已被使用")
		}
		if redemption.ExpiredTime != 0 && redemption.ExpiredTime < common.GetTimestamp() {
			return errors.New("该兑换码已过期")
		}
		redemption.RedemptionType = NormalizeRedemptionType(redemption.RedemptionType)
		switch redemption.RedemptionType {
		case RedemptionTypeSubscription:
			if redemption.SubscriptionPlanId <= 0 {
				return errors.New("该兑换码未配置订阅套餐")
			}
			plan, err := getSubscriptionPlanByIdTx(tx, redemption.SubscriptionPlanId)
			if err != nil {
				return errors.New("兑换码绑定的订阅套餐不存在")
			}
			sub, err := CreateUserSubscriptionFromPlanTx(tx, userId, plan, "redemption")
			if err != nil {
				return err
			}
			redeemResult.RedemptionType = RedemptionTypeSubscription
			redeemResult.SubscriptionPlanId = plan.Id
			redeemResult.SubscriptionPlanTitle = plan.Title
			redeemResult.UserSubscriptionId = sub.Id
			upgradeGroup = strings.TrimSpace(plan.UpgradeGroup)
		default:
			err = tx.Model(&User{}).Where("id = ?", userId).Update("quota", gorm.Expr("quota + ?", redemption.Quota)).Error
			if err != nil {
				return err
			}
			redeemResult.RedemptionType = RedemptionTypeQuota
			redeemResult.Quota = redemption.Quota
		}
		redemption.RedeemedTime = common.GetTimestamp()
		redemption.Status = common.RedemptionCodeStatusUsed
		redemption.UsedUserId = userId
		err = tx.Save(redemption).Error
		return err
	})
	if err != nil {
		common.SysError("redemption failed: " + err.Error())
		return nil, ErrRedeemFailed
	}
	if upgradeGroup != "" {
		_ = UpdateUserGroupCache(userId, upgradeGroup)
	}
	switch redeemResult.RedemptionType {
	case RedemptionTypeSubscription:
		RecordLog(userId, LogTypeTopup, fmt.Sprintf("通过兑换码兑换订阅 %s，兑换码ID %d", redeemResult.SubscriptionPlanTitle, redemption.Id))
	default:
		RecordLog(userId, LogTypeTopup, fmt.Sprintf("通过兑换码充值 %s，兑换码ID %d", logger.LogQuota(redemption.Quota), redemption.Id))
	}
	return redeemResult, nil
}

func (redemption *Redemption) Insert() error {
	var err error
	err = DB.Create(redemption).Error
	return err
}

func (redemption *Redemption) SelectUpdate() error {
	// This can update zero values
	return DB.Model(redemption).Select("redeemed_time", "status").Updates(redemption).Error
}

// Update Make sure your token's fields is completed, because this will update non-zero values
func (redemption *Redemption) Update() error {
	var err error
	err = DB.Model(redemption).Select("name", "status", "quota", "redemption_type", "subscription_plan_id", "redeemed_time", "expired_time").Updates(redemption).Error
	return err
}

func (redemption *Redemption) Delete() error {
	var err error
	err = DB.Delete(redemption).Error
	return err
}

func DeleteRedemptionById(id int) (err error) {
	if id == 0 {
		return errors.New("id 为空！")
	}
	redemption := Redemption{Id: id}
	err = DB.Where(redemption).First(&redemption).Error
	if err != nil {
		return err
	}
	return redemption.Delete()
}

func DeleteInvalidRedemptions() (int64, error) {
	now := common.GetTimestamp()
	result := DB.Where("status IN ? OR (status = ? AND expired_time != 0 AND expired_time < ?)", []int{common.RedemptionCodeStatusUsed, common.RedemptionCodeStatusDisabled}, common.RedemptionCodeStatusEnabled, now).Delete(&Redemption{})
	return result.RowsAffected, result.Error
}

func attachRedemptionPlanTitle(redemption *Redemption) error {
	if redemption == nil {
		return nil
	}
	redemption.RedemptionType = NormalizeRedemptionType(redemption.RedemptionType)
	redemption.SubscriptionPlanTitle = ""
	if redemption.RedemptionType != RedemptionTypeSubscription || redemption.SubscriptionPlanId <= 0 {
		return nil
	}
	plan, err := GetSubscriptionPlanById(redemption.SubscriptionPlanId)
	if err != nil {
		return nil
	}
	redemption.SubscriptionPlanTitle = plan.Title
	return nil
}

func attachRedemptionPlanTitles(redemptions []*Redemption) error {
	for _, redemption := range redemptions {
		if err := attachRedemptionPlanTitle(redemption); err != nil {
			return err
		}
	}
	return nil
}
