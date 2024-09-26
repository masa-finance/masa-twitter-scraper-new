package features

var CommonFeatures = map[string]interface{}{
	"creator_subscriptions_tweet_preview_api_enabled":                   true,
	"responsive_web_graphql_exclude_directive_enabled":                  true,
	"responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
	"responsive_web_graphql_timeline_navigation_enabled":                true,
	"verified_phone_label_enabled":                                      false,
}

var TweetFeatures = MergeFeatures(CommonFeatures, map[string]interface{}{
	"tweetypie_unmention_optimization_enabled":                                true,
	"vibe_api_enabled":                                                        true,
	"responsive_web_edit_tweet_api_enabled":                                   true,
	"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
	"view_counts_everywhere_api_enabled":                                      true,
	"longform_notetweets_consumption_enabled":                                 true,
	"tweet_awards_web_tipping_enabled":                                        false,
	"freedom_of_speech_not_reach_fetch_enabled":                               true,
	"standardized_nudges_misinfo":                                             true,
	"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
	"longform_notetweets_rich_text_read_enabled":                              true,
	"longform_notetweets_inline_media_enabled":                                true,
	"responsive_web_enhance_cards_enabled":                                    false,
})

var BaseProfileFeatures = MergeFeatures(CommonFeatures, map[string]interface{}{
	"hidden_profile_subscriptions_enabled":             true,
	"highlights_tweets_tab_ui_enabled":                 true,
	"responsive_web_twitter_article_notes_tab_enabled": true,
	"rweb_tipjar_consumption_enabled":                  true,
	"subscriptions_feature_can_gift_premium":           true,
})

var ProfileFeatures = MergeFeatures(CommonFeatures, map[string]interface{}{
	"subscriptions_verification_info_is_identity_verified_enabled": true,
	"subscriptions_verification_info_verified_since_enabled":       true,
})

var UserFeatures = MergeFeatures(CommonFeatures, map[string]interface{}{
	"c9s_tweet_anatomy_moderator_badge_enabled": true,
	"tweetypie_unmention_optimization_enabled":  true,
	"standardized_nudges_misinfo":               true,
	"freedom_of_speech_not_reach_fetch_enabled": true,
})

var SpaceFeatures = MergeFeatures(CommonFeatures, map[string]interface{}{
	"spaces_2022_h2_spaces_communities":                    true,
	"spaces_2022_h2_clipping":                              true,
	"communities_web_enable_tweet_community_results_fetch": true,
	"c9s_tweet_anatomy_moderator_badge_enabled":            true,
	"articles_preview_enabled":                             true,
	"tweetypie_unmention_optimization_enabled":             true,
})

// MergeFeatures combines the base features with overrides.
func MergeFeatures(base, overrides map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{}, len(base))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overrides {
		merged[k] = v
	}
	return merged
}
