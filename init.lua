local http = require("coro-http")
local json = require("json")
local timer = require("timer")
local uv = require("uv")

local ropi = {
	cache = {
		users = {},
		weakUsers = {},
		avatars = {},
		groups = {}
	},
	cookie = nil,
	Requests = {},
	Ratelimits = {},
	ActiveBuckets = {},
	RequestOrigins = {},
	Domains = {
		{
			name = "roblox",
			parse = function(api)
				return api .. ".roblox.com"
			end
		},
		{
			name = "RoProxy",
			parse = function(api)
				return api .. ".RoProxy.com"
			end
		},
		{
			name = "ropiproxy",
			parse = function(api)
				return "ropiproxy.vercel.app/" .. api
			end
		},
		{
			name = "ropiproxytwo",
			parse = function(api)
				return "ropiproxytwo.vercel.app/" .. api
			end
		},
		{
			name = "ropiproxythree",
			parse = function(api)
				return "ropiproxythree.vercel.app/" .. api
			end
		}
	}
}

-- general utilities

local function split(str, delim)
	local ret = {}
	if not str then
		return ret
	end
	if not delim or delim == "" then
		for c in string.gmatch(str, ".") do
			table.insert(ret, c)
		end
		return ret
	end
	local n = 1
	while true do
		local i, j = find(str, delim, n)
		if not i then
			break
		end
		table.insert(ret, sub(str, n, i - 1))
		n = j + 1
	end
	table.insert(ret, sub(str, n))
	return ret
end

local function hasHeader(headers, name)
	for _, header in pairs(headers) do
		if header[1]:lower() == name:lower() then
			return true
		end
	end

	return false
end

local function fromISO(iso)
	if not iso then
		return
	end

	local year, month, day, hour, min, sec, ms = iso:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+).(%d+)Z")

	if not year or not month or not day or not hour or not min or not sec or not ms then
		return
	end

	local epoch = os.time({
		year = tonumber(year),
		month = tonumber(month),
		day = tonumber(day),
		hour = tonumber(hour),
		min = tonumber(min),
		sec = tonumber(sec),
		isdst = false
	})

	return epoch + (tonumber(ms) / 1000)
end

local function realtime()
	local seconds, microseconds = uv.gettimeofday()

	return seconds + (microseconds / 1000000)
end

local function safeResume(co, ...)
	if type(co) ~= "thread" then
		return false, "Invalid coroutine"
	end
	if coroutine.status(co) ~= "suspended" then
		return false, "Coroutine not suspended"
	end

	local ok, result = coroutine.resume(co, ...)
	if not ok then
		return false, result
	end
	return true, result
end

-- cache utilities

local function intoCache(item, category)
	for i = #ropi.cache[category], 1, -1 do
		local u = ropi.cache[category][i]
		if u.id == item.id then
			table.remove(ropi.cache[category], i)
		end
	end

	table.insert(ropi.cache[category], item)

	return item
end

local function fromCache(query, category)
	for _, item in pairs(ropi.cache[category]) do
		if (tostring(query):lower() == item.name:lower()) or (tonumber(query) == item.id) then
			return item
		end
	end
end

-- objects

local function User(data)
	return {
		name = data.name,
		displayName = data.displayName,
		id = data.id,
		description = data.description,
		avatar = ropi.GetAvatarHeadShot(data.id) or "https://duckybot.xyz/images/icons/RobloxConfused.png",
		verified = not not data.hasVerifiedBadge,
		banned = not not data.isBanned,
		created = fromISO(data.created),
		profile = "https://roblox.com/users/" .. data.id .. "/profile",
		hyperlink = "[" .. data.name .. "](<https://roblox.com/users/" .. data.id .. "/profile>)"
	}
end

local function WeakUser(data)
	return {
		displayName = data.displayName,
		name = data.name,
		id = data.id,
		avatar = data.avatar or "https://duckybot.xyz/images/icons/RobloxConfused.png",
		verified = not not data.hasVerifiedBadge,
		profile = "https://roblox.com/users/" .. data.id .. "/profile",
		hyperlink = "[" .. data.name .. "](<https://roblox.com/users/" .. data.id .. "/profile>)"
	}
end

local function GroupUser(data)
	return {
		name = data.username,
		displayName = data.displayName,
		id = data.userId,
		verified = not not data.hasVerifiedBadge,
		profile = "https://roblox.com/users/" .. data.userId .. "/profile",
		hyperlink = "[" .. data.username .. "](<https://roblox.com/users/" .. data.userId .. "/profile>)"
	}
end

local function Group(data)
	return {
		name = data.name,
		id = data.id,
		description = data.description,
		owner = ropi.GetUser(data.owner.userId),
		members = data.memberCount,
		shout = data.shout,
		verified = not not data.hasVerifiedBadge,
		public = not not data.publicEntryAllowed,
		link = "https://www.roblox.com/communities/" .. data.id,
		hyperlink = "[" .. data.name .. "](<https://www.roblox.com/communities/" .. data.id .. ">)"
	}
end

local function Transaction(data, loadUser)
	return {
		hash = data.idHash,
		created = fromISO(data.created),
		pending = data.isPending,
		user = (loadUser and ropi.GetUser(data.agent.id)) or {id = data.agent.id},
		item = {
			name = data.details.name,
			id = data.details.id,
			type = data.details.type,
			place = (data.details.place and {
				name = data.details.place.name,
				id = data.details.place.placeId,
				game = data.details.place.universeId
			}) or nil
		},
		price = math.floor((data.currency.amount / 0.7) + 0.5),
		taxed = math.floor(data.currency.amount + 0.5),
		token = data.purchaseToken
	}
end

local function Error(code, message)
	if _G.Client then
		_G.Client:error("[ROPI] | " .. tostring(message))
	end

	return {
		code = code,
		message = message
	}
end

-- request handler

function ropi:queue(request)
	request.timestamp = os.time()

	local co, main = coroutine.running()
	if not co or main or not coroutine.isyieldable(co) then
		return "ropi:queue must be called from inside a yieldable coroutine"
	end

	request.co = co

	local b = request.api

	ropi.Requests[b] = ropi.Requests[b] or {}
	table.insert(ropi.Requests[b], request)

	if request.origin then
		ropi.RequestOrigins[request.origin] = (ropi.RequestOrigins[request.origin] and ropi.RequestOrigins[request.origin] + 1) or 0
	end

	return coroutine.yield()
end

function ropi:dump()
	local now = realtime()

	for bucket, list in pairs(ropi.Requests) do
		ropi.Ratelimits[bucket] = ropi.Ratelimits[bucket] or {}
		local bucketRatelimit = ropi.Ratelimits[bucket]

		if not ropi.ActiveBuckets[bucket] and #list > 0 and (not bucketRatelimit.retryAt or now >= bucketRatelimit.retryAt) then
			ropi.ActiveBuckets[bucket] = true

			local timeoutTimer = uv.new_timer()
			uv.timer_start(timeoutTimer, 10000, 0, function()
				if ropi.ActiveBuckets[bucket] then
					Error("Timeout: Forcing unlock of bucket " .. tostring(bucket))
					ropi.ActiveBuckets[bucket] = nil
				end
				uv.close(timeoutTimer)
			end)

			coroutine.wrap(function()
				local ok, err = pcall(function()
					table.sort(list, function(a, b)
						return a.timestamp < b.timestamp
					end)

					local req = list[1]
					if not req then
						return
					end

					local domainsToTry = {}
					if req.domains == true or req.domains == nil then
						domainsToTry = ropi.Domains
					elseif type(req.domains) == "table" then
						for _, domainName in ipairs(req.domains) do
							for _, domainDef in ipairs(ropi.Domains) do
								if domainDef.name == domainName then
									table.insert(domainsToTry, domainDef)
									break
								end
							end
						end
					end

					if #domainsToTry == 0 then
						domainsToTry = ropi.Domains
					end

					bucketRatelimit.lastDomainIndex = bucketRatelimit.lastDomainIndex or 0

					local chosenDomain
					local start_index = bucketRatelimit.lastDomainIndex % #domainsToTry + 1

					for i = 1, #domainsToTry do
						local index = (start_index + i - 2) % #domainsToTry + 1
						local domain = domainsToTry[index]
						local domainRatelimit = bucketRatelimit[domain.name]

						if not domainRatelimit or not domainRatelimit.retry or now >= (domainRatelimit.updated + domainRatelimit.retry) then
							chosenDomain = domain
							bucketRatelimit.lastDomainIndex = index
							break
						end
					end

					if chosenDomain then
						bucketRatelimit.retryAt = nil
						local okReq, response, result = ropi:request(req.api, req.method, req.endpoint, req.headers, req.body, chosenDomain, req.expectedCode, req.version)

						if not okReq and type(result) == "table" and result.code == 429 then
							local retryAfter = 1
							for _, header in pairs(result) do
								if type(header) == "table" and type(header[1]) == "string" and header[1]:lower() == "retry-after" then
									retryAfter = tonumber(header[2]) or 1
								end
							end

							Error("The " .. (bucket or "unknown") .. " bucket on domain " .. chosenDomain.name .. " was ratelimited, requeueing for " .. retryAfter .. "s.")

							bucketRatelimit[chosenDomain.name] = {
								updated = realtime(),
								retry = retryAfter
							}
						else
							table.remove(list, 1)
							if #list == 0 then
								ropi.Requests[bucket] = nil
							end
							safeResume(req.co, okReq, response, result)
						end
					else
						local soonestRetryAt
						for _, domain in ipairs(domainsToTry) do
							local domainRatelimit = bucketRatelimit[domain.name]
							if domainRatelimit and domainRatelimit.retry then
								local retryAt = domainRatelimit.updated + domainRatelimit.retry
								if now < retryAt then
									if not soonestRetryAt or retryAt < soonestRetryAt then
										soonestRetryAt = retryAt
									end
								end
							end
						end
						if soonestRetryAt then
							bucketRatelimit.retryAt = soonestRetryAt
						end
					end
				end)

				ropi.ActiveBuckets[bucket] = nil
				if not uv.is_closing(timeoutTimer) then
					uv.close(timeoutTimer)
				end

				if not ok then
					Error("Error during bucket dump:", err)
				end
			end)()
		end
	end
end

function ropi:request(api, method, endpoint, headers, body, domain, expectedCode, version)
	local url = "https://" .. domain.parse(api) .. "/" .. (version or "v1") .. "/" .. endpoint

	headers = type(headers) == "table" and headers or {}
	if not hasHeader(headers, "Content-Type") then
		table.insert(headers, {
			"Content-Type",
			"application/json"
		})
	end

	body = (body and type(body) == "table" and json.encode(body)) or (type(body) == "string" and body) or nil

	local success, result, response = pcall(http.request, method, url, headers, body, {
		timeout = 5000
	})
	response = (response and type(response) == "string" and json.decode(response)) or nil

	if not success then
		return false, Error(500, "An unknown error occurred."), result
	end

	if result.code == 200 then
		return true, response, result
	elseif expectedCode and result.code == expectedCode then
		return true, response, result
	else
		local err = (response and response.errors and response.errors[1] and Error(response.errors[1].code, response.errors[1].message)) or Error(result.code, result.reason)
		return false, err, result
	end
end

-- api functions

function ropi.SetCookie(token)
	ropi.cookie = ".ROBLOSECURITY=" .. token

	return true
end

function ropi.GetToken()
	local success, response, result = ropi:queue({
		api = "itemconfiguration",
		method = "PATCH",
		endpoint = "collectibles/xcsrftoken",
		domains = {"roblox"},
		expectedCode = 403,
		headers = {
			{
				"Cookie",
				ropi.cookie
			}
		}
	})

	if not success or not result or result.code ~= 403 then
		return false, response
	end

	for _, header in pairs(result) do
		if type(header) == "table" and type(header[1]) == "string" and header[1]:lower() == "x-csrf-token" then
			return true, header[2]
		end
	end

	return false, Error(500, "A token was not provided by the server.")
end

function ropi.GetAvatarHeadShots(ids, opts, refresh)
	local debugInfo
	for i = 1, 10 do
		debugInfo = debug.getinfo(i, "Sl")
		if (debugInfo) and (not debugInfo.short_src:lower():find("ropi")) and (debugInfo.what ~= "C") then
			break
		end
	end
	local origin = (debugInfo and (debugInfo.short_src .. ":" .. debugInfo.currentline)) or nil

	if type(ids) ~= "table" then
		return nil, Error(400, "An invalid ids table was provided to SearchUsers.")
	end

	for i, id in pairs(ids) do
		if type(id) == "string" then
			ids[i] = tonumber(id)
		end
	end

	opts = opts or {}
	local options = {
		size = opts.size or 720,
		format = opts.format or "Png",
		isCircular = not not opts.isCircular
	}

	local avatars = {}

	if not refresh then
		for i = #ids, 1, -1 do
			local id = ids[i]
			local cached = ropi.cache.avatars[id]
			if cached then
				avatars[id] = cached
				table.remove(ids, i)
			end
		end
	end

	local errorResponse

	if next(ids) then
		local success, response = ropi:queue({
			api = "thumbnails",
			method = "GET",
			domains = true,
			endpoint = "users/avatar-headshot?userIds=" .. table.concat(ids, ",") .. "&size=" .. options.size .. "x" .. options.size .. "&format=Png&isCircular=" .. tostring(options.isCircular),
			origin = origin
		})

		if success and type(response) == "table" and type(response.data) == "table" and next(response.data) then
			for _, avatarData in pairs(response.data) do
				if type(avatarData) == "table" and avatarData.targetId and avatarData.state == "Completed" and avatarData.imageUrl then
					ropi.cache.avatars[avatarData.targetId] = avatarData.imageUrl
					avatars[avatarData.targetId] = avatarData.imageUrl
				end
			end
		else
			errorResponse = response
		end
	end

	if not next(avatars) and errorResponse then
		return nil, errorResponse
	else
		return avatars
	end
end

function ropi.GetAvatarHeadShot(id, opts, refresh)
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetAvatarHeadShot.")
	end

	local avatars, error = ropi.GetAvatarHeadShots({id}, opts, refresh)

	if not error and type(avatars) == "table" and avatars[id] then
		return avatars[id]
	else
		return nil, error or "Failed to get avatar headshot"
	end
end

function ropi.GetUsers(ids, opts, refresh)
	local debugInfo
	for i = 1, 10 do
		debugInfo = debug.getinfo(i, "Sl")
		if (debugInfo) and (not debugInfo.short_src:lower():find("ropi")) and (debugInfo.what ~= "C") then
			break
		end
	end
	local origin = (debugInfo and (debugInfo.short_src .. ":" .. debugInfo.currentline)) or nil

	if type(ids) ~= "table" then
		return nil, Error(400, "An invalid ids table was provided to SearchUsers.")
	end

	for i, id in pairs(ids) do
		if type(id) == "string" then
			ids[i] = tonumber(id)
		end
	end

	opts = opts or {}
	local options = {
		fullObject = opts.fullObject,
		avatars = opts.avatars,
		dictionary = opts.dictionary,
		fillUnknown = opts.fillUnknown
	}

	local users = {}

	if not refresh then
		for i = #ids, 1, -1 do
			local id = ids[i]
			if type(id) == "string" then
				local cached = fromCache(id, "users") or (not options.fullObject and fromCache(id, "weakUsers"))
				if cached then
					table.insert(users, cached)
					table.remove(ids, i)
				end
			end
		end
	end

	local errorResponse

	if next(ids) then
		local success, response = ropi:queue({
			api = "users",
			method = "POST",
			domains = {
				"roblox",
				"RoProxy",
				"ropiproxy",
				"ropiproxytwo",
				"ropiproxythree"
			},
			endpoint = "users",
			body = {
				userIds = ids,
				excludeBannedUsers = true
			},
			origin = origin
		})

		if success and type(response) == "table" and type(response.data) == "table" and next(response.data) then
			local avatars
			if options.avatars and not options.fullObject then
				local userIds = {}
				for _, userData in pairs(response.data) do
					if type(userData) == "table" and userData.id then
						table.insert(userIds, userData.id)
					end
				end
				if #userIds > 0 then
					avatars = ropi.GetAvatarHeadShots(userIds, opts, refresh)
				end
			end

			for _, userData in pairs(response.data) do
				if type(userData) == "table" and userData.id then
					if options.fullObject then
						local user = ropi.GetUser(userData.id)
						if type(user) == "table" then
							if options.dictionary then
								users[user.id] = user
							else
								table.insert(users, user)
							end
						end
					else
						if avatars and avatars[userData.id] then
							userData.avatar = avatars[userData.id]
						end

						if options.dictionary then
							users[userData.id] = intoCache(WeakUser(userData), "weakUsers")
						else
							table.insert(users, intoCache(WeakUser(userData), "weakUsers"))
						end
					end
				end
			end
		else
			errorResponse = response
		end
	end

	if options.fillUnknown then
		for _, id in pairs(ids) do
			local found
			for _, user in pairs(users) do
				if user.id == id then
					found = true
					break
				end
			end

			if not found then
				local user = {
					id = id,
					displayName = "UnknownUser",
					name = "UnknownUser",
					avatar = "https://duckybot.xyz/images/icons/RobloxConfused.png",
					profile = "https://roblox.com/users/" .. id .. "/profile",
					verified = false,
					hyperlink = "[UnknownUser](<https://roblox.com/users/" .. id .. "/profile>)"
				}

				if options.dictionary then
					users[user.id] = user
				else
					table.insert(users, user)
				end
			end
		end
	end

	if not next(users) and errorResponse then
		return nil, errorResponse
	else
		return users
	end
end

function ropi.GetUser(id, refresh)
	local debugInfo
	for i = 1, 10 do
		debugInfo = debug.getinfo(i, "Sl")
		if (debugInfo) and (not debugInfo.short_src:lower():find("ropi")) and (debugInfo.what ~= "C") then
			break
		end
	end
	local origin = (debugInfo and (debugInfo.short_src .. ":" .. debugInfo.currentline)) or nil

	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetUser.")
	end

	if not refresh then
		local cached = fromCache(id, "users")
		if cached then
			return cached
		end
	end

	local success, user = ropi:queue({
		api = "users",
		method = "GET",
		domains = true,
		endpoint = "users/" .. id,
		origin = origin
	})

	if success and user and user.name and user.displayName and user.id then
		return intoCache(User(user), "users")
	else
		return nil, user
	end
end

function ropi.SearchUsers(usernames, opts, refresh)
	local debugInfo
	for i = 1, 10 do
		debugInfo = debug.getinfo(i, "Sl")
		if (debugInfo) and (not debugInfo.short_src:lower():find("ropi")) and (debugInfo.what ~= "C") then
			break
		end
	end
	local origin = (debugInfo and (debugInfo.short_src .. ":" .. debugInfo.currentline)) or nil

	if type(usernames) ~= "table" then
		return nil, Error(400, "An invalid username table was provided to SearchUsers.")
	end

	opts = opts or {}
	local options = {
		fullObject = opts.fullObject,
		avatars = opts.avatars,
		dictionary = opts.dictionary
	}

	local users = {}

	if not refresh then
		for i = #usernames, 1, -1 do
			local username = usernames[i]
			if type(username) == "string" then
				local cached = fromCache(username, "users") or (not options.fullObject and fromCache(username, "weakUsers"))
				if cached then
					table.insert(users, cached)
					table.remove(usernames, i)
				end
			end
		end
	end

	local errorResponse

	if next(usernames) then
		local success, response = ropi:queue({
			api = "users",
			method = "POST",
			domains = {
				"roblox",
				"RoProxy",
				"ropiproxy",
				"ropiproxytwo",
				"ropiproxythree"
			},
			endpoint = "usernames/users",
			body = {
				usernames = usernames,
				excludeBannedUsers = true
			},
			origin = origin
		})

		if success and type(response) == "table" and type(response.data) == "table" and next(response.data) then
			local avatars
			if options.avatars and not options.fullObject then
				local userIds = {}
				for _, userData in pairs(response.data) do
					if type(userData) == "table" and userData.id then
						table.insert(userIds, userData.id)
					end
				end
				if #userIds > 0 then
					avatars = ropi.GetAvatarHeadShots(userIds, opts, refresh)
				end
			end

			for _, userData in pairs(response.data) do
				if type(userData) == "table" and userData.id then
					if options.fullObject then
						local user = ropi.GetUser(userData.id)
						if type(user) == "table" then
							if options.dictionary then
								users[user.id] = user
							else
								table.insert(users, user)
							end
						end
					else
						if avatars and avatars[userData.id] then
							userData.avatar = avatars[userData.id]
						end

						if options.dictionary then
							users[userData.id] = intoCache(WeakUser(userData), "weakUsers")
						else
							table.insert(users, intoCache(WeakUser(userData), "weakUsers"))
						end
					end
				end
			end
		else
			errorResponse = response
		end
	end

	if not next(users) and errorResponse then
		return nil, errorResponse
	else
		return users
	end
end

function ropi.SearchUser(name, refresh)
	if type(name) ~= "string" and type(name) ~= "number" then
		return nil, Error(400, "An invalid name/ID was provided to SearchUser.")
	end

	if tonumber(name) then
		return ropi.GetUser(name, refresh)
	end

	local users = ropi.SearchUsers({name}, {fullObject = true}, refresh)

	if type(users) == "table" and users[1] then
		return users[1]
	else
		return nil, users
	end
end

function ropi.GetGroup(id, refresh)
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetGroup.")
	end

	if not refresh then
		local cached = fromCache(id, "groups")
		if cached then
			return cached
		end
	end

	local success, group = ropi:queue({
		api = "groups",
		method = "GET",
		proxy = true,
		endpoint = "groups/" .. id
	})

	if success and group and group.name and group.id then
		return intoCache(Group(group), "groups")
	else
		return nil, group
	end
end

function ropi.GetGroupMembers(id, full)
	local members = {}
	local cursor = nil

	repeat
		local url = "groups/" .. id .. "/users?limit=100" .. ((cursor and "&cursor=" .. cursor) or "")
		local success, response = ropi:queue({
			api = "groups",
			method = "GET",
			proxy = true,
			endpoint = url
		})

		if success and response then
			for _, userdata in pairs(response.data or {}) do
				table.insert(members, (full and ropi.GetUser(userdata.user.userId)) or GroupUser(userdata.user))
			end

			cursor = response.nextPageCursor
		else
			break
		end
	until not cursor

	return true, members
end

function ropi.GetGroupTransactions(id, pages, loadUsers) -- pass true for pages to get all pages
	if not ropi.cookie then
		return nil, Error(400, ".ROBLOSECURITY cookie has not yet been set.")
	end

	local success, token = ropi.GetToken()

	if not success then
		return token
	end

	local transactions = {}
	local cursor = nil
	local pagesFetched = 0

	repeat
		local url = "groups/" .. id .. "/transactions?limit=100&transactionType=Sale" .. ((cursor and "&cursor=" .. cursor) or "")
		local success, response, result = ropi:queue({
			api = "economy",
			method = "GET",
			endpoint = url,
			domains = {
				"roblox"
			},
			headers = {
				{
					"Cookie",
					ropi.cookie
				},
				{
					"X-Csrf-Token",
					token
				}
			},
			version = "v2"
		})

		if success and response then
			for _, transactionData in pairs(response.data or {}) do
				table.insert(transactions, Transaction(transactionData, loadUsers))
			end

			cursor = response.nextPageCursor
			pagesFetched = pagesFetched + 1
		else
			break
		end
	until not cursor or (not pages) or (type(pages) == "number" and pagesFetched >= pages)

	table.sort(transactions, function(a, b)
		return a.created > b.created
	end)

	return transactions
end

function ropi.SetAssetPrice(collectibleID, price)
	if not ropi.cookie then
		return nil, Error(400, ".ROBLOSECURITY cookie has not yet been set.")
	end

	local success, token = ropi.GetToken()

	if not success then
		return token
	end

	if (not collectibleID) or type(collectibleID) ~= "string" then
		return nil, Error(400, "Collectible ID was not provided as a string.")
	elseif collectibleID:len() < 10 then
		return nil, Error(400, "A malformed collectible ID was provided.")
	end

	local success, response, result = ropi:queue({
		api = "itemconfiguration",
		method = "PATCH",
		endpoint = "collectibles/" .. collectibleID,
		domains = {
			"roblox"
		},
		headers = {
			{
				"Cookie",
				ropi.cookie
			},
			{
				"X-Csrf-Token",
				token
			}
		},
		body = {
			saleLocationConfiguration = {
				saleLocationType = 1,
				places = {}
			},
			saleStatus = 0,
			quantityLimitPerUser = 0,
			resaleRestriction = 2,
			priceInRobux = price,
			priceOffset = 0,
			isFree = false
		}
	})

	if success then
		return true
	else
		return false, result
	end
end

local dumpTimer = uv.new_timer()
uv.timer_start(dumpTimer, 0, 5, function()
	if next(ropi.Requests) then
		ropi:dump()
	end
end)

return ropi
