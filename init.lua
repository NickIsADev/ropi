local http = require("coro-http")
local json = require("json")
local timer = require("timer")
local uv = require("uv")

local ropi = {
	cache = {
		users = {},
		avatars = {},
		groups = {}
	},
	cookie = nil,
	Requests = {},
	Ratelimits = {},
	ActiveBuckets = {},
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
		},
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
		if (type(query) == "string" and item.name:lower() == query:lower()) or (type(query) == "number" and item.id == query) then
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

local function Transaction(data)
	return {
		hash = data.idHash,
		created = fromISO(data.created),
		pending = data.isPending,
		user = ropi.GetUser(data.agent.id),
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

	return coroutine.yield()
end

function ropi:dump()
	local now = realtime()

	for bucket, list in pairs(ropi.Requests) do
		if not ropi.ActiveBuckets[bucket] and #list > 0 then
			ropi.ActiveBuckets[bucket] = true

			coroutine.wrap(function()
				table.sort(list, function(a, b)
					return a.timestamp < b.timestamp
				end)

				local req = list[1]
				if not req then
					ropi.ActiveBuckets[bucket] = nil
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

				ropi.Ratelimits[bucket] = ropi.Ratelimits[bucket] or {}
				local bucket_ratelimits = ropi.Ratelimits[bucket]
				bucket_ratelimits.lastDomainIndex = bucket_ratelimits.lastDomainIndex or 0

				local chosenDomain = nil
				if #domainsToTry > 0 then
					local start_index = bucket_ratelimits.lastDomainIndex % #domainsToTry + 1

					for i = 1, #domainsToTry do
						local index = (start_index + i - 2) % #domainsToTry + 1
						local domain = domainsToTry[index]
						local domain_ratelimit = bucket_ratelimits[domain.name]

						if not domain_ratelimit or not domain_ratelimit.retry or now >= (domain_ratelimit.updated + domain_ratelimit.retry) then
							chosenDomain = domain
							bucket_ratelimits.lastDomainIndex = index
							break
						end
					end
				end

				if chosenDomain then
					local ok, response, result = ropi:request(req.api, req.method, req.endpoint, req.headers, req.body, chosenDomain, req.version)

					if not ok and result.code == 429 then
						local retryAfter = 1
						for _, header in pairs(result) do
							if type(header) == "table" and type(header[1]) == "string" and header[1]:lower() == "retry-after" then
								retryAfter = tonumber(header[2]) or 1
							end
						end

						print("[ROPI] | The " .. (bucket or "unknown") .. " bucket on domain " .. chosenDomain.name .. " was ratelimited, requeueing for " .. retryAfter .. "s.")

						bucket_ratelimits[chosenDomain.name] = {
							updated = realtime(),
							retry = retryAfter,
						}
					else
						table.remove(list, 1)
						if #list == 0 then
							ropi.Requests[bucket] = nil
						end
						safeResume(req.co, ok, response, result)
					end
				end)

				if not success then
					print("[ROPI] | An error occurred while attempting to dump the " .. (bucket or "unknown") .. " bucket: " .. tostring(err))
				end

				ropi.ActiveBuckets[bucket] = nil
			end)()
		end
	end
end

function ropi:request(api, method, endpoint, headers, body, domain, version)
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
		headers = {
			{
				"Cookie",
				ropi.cookie
			}
		}
	})

	if not success then
		return false, response
	end

	for _, header in pairs(result) do
		if type(header) == "table" and type(header[1]) == "string" and header[1]:lower() == "x-csrf-token" then
			return true, header[2]
		end
	end

	return false, Error(500, "A token was not provided by the server.")
end

function ropi.GetAvatarHeadShot(id, opts, refresh)
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetAvatarHeadShot.")
	end

	opts = opts or {}
	id = tonumber(id) or 0

	if (not refresh) and ropi.cache.avatars[id] then
		return ropi.cache.avatars[id]
	end

	local options = {
		size = opts.size or 720,
		format = opts.format or "Png",
		isCircular = not not opts.isCircular
	}

	local success, response = ropi:queue({
		api = "thumbnails",
		method = "GET",
		proxy = true,
		endpoint = "users/avatar-headshot?userIds=" .. id .. "&size=" .. options.size .. "x" .. options.size .. "&format=Png&isCircular=" .. tostring(options.isCircular)
	})

	if success and response and response.data then
		if response.data[1] and response.data[1].state == "Completed" and response.data[1].imageUrl then
			ropi.cache.avatars[id] = response.data[1].imageUrl

			return response.data[1].imageUrl
		end
	end

	return nil, response
end

function ropi.GetUser(id, refresh)
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
		endpoint = "users/" .. id
	})

	if success and user and user.name and user.displayName and user.id then
		return intoCache(User(user), "users")
	else
		return nil, user
	end
end

function ropi.SearchUser(name, refresh)
	if type(name) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid name/ID was provided to SearchUser.")
	end

	if tonumber(name) then
		return ropi.GetUser(name, refresh)
	end

	if not refresh then
		local cached = fromCache(name, "users")
		if cached then
			return cached
		end
	end

	local success, response = ropi:queue({
		api = "users",
		method = "POST",
		domains = {"roblox", "RoProxy", "ropiproxy", "ropiproxytwo", "ropiproxythree"},
		endpoint = "usernames/users",
		body = {
			usernames = {
				name
			},
			excludeBannedUsers = true
		}
	})

	if success and response.data and response.data[1] and response.data[1].name and response.data[1].name:lower() == name:lower() and response.data[1].displayName and response.data[1].id then
		return ropi.GetUser(response.data[1].id)
	else
		return nil, response
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

function ropi.GetGroupTransactions(id, all)
	if not ropi.cookie then
		return nil, Error(400, ".ROBLOSECURITY cookie has not yet been set.")
	end

	local success, token = ropi.GetToken()

	if not success then
		return token
	end

	local transactions = {}
	local cursor = nil

	repeat
		local url = "groups/" .. id .. "/transactions?limit=100&transactionType=Sale" .. ((cursor and "&cursor=" .. cursor) or "")
		local success, response, result = ropi:queue({
			api = "economy",
			method = "GET",
			endpoint = url,
			domains = {"roblox"},
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
				table.insert(transactions, Transaction(transactionData))
			end

			cursor = response.nextPageCursor
		else
			break
		end
	until (not cursor) or (not all)

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
		domains = {"roblox"},
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
