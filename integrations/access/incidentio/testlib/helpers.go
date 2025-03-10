/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package testlib

import (
	"context"

	"github.com/gravitational/teleport/integrations/access/incidentio"
	"github.com/stretchr/testify/require"
)

func (s *IncidentBaseSuite) checkPluginData(ctx context.Context, reqID string, cond func(incidentio.PluginData) bool) incidentio.PluginData {
	t := s.T()
	t.Helper()

	for {
		rawData, err := s.Ruler().PollAccessRequestPluginData(ctx, "incidentio", reqID)
		require.NoError(t, err)
		if data := incidentio.DecodePluginData(rawData); cond(data) {
			return data
		}
	}
}
